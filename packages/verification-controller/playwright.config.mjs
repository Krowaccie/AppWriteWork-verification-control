export default {
  testDir: './e2e',
  testMatch: 'production-readonly.spec.mjs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'line',
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        serviceWorkers: 'block',
        storageState: undefined,
      },
    },
  ],
  use: {
    acceptDownloads: false,
    serviceWorkers: 'block',
    storageState: undefined,
  },
};
