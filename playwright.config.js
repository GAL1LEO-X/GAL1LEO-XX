const { defineConfig, devices } = require('@playwright/test');
const path = require('node:path');
const results = process.env.PLUGINS_TEST_RESULTS_DIR || 'work/test-results';
const python = process.env.PLUGINS_TEST_PYTHON || '.venvs/whatsapp/bin/python';
const shellQuote = value => "'" + value.replace(/'/g, "'\\''") + "'";
module.exports = defineConfig({
  testDir: './tests/browser',
  timeout: 60000,
  expect: { timeout: 12000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  outputDir: path.join(results, 'browser-artifacts'),
  reporter: [['list'], ['junit', { outputFile: path.join(results, 'browser.xml') }]],
  use: { baseURL: 'http://127.0.0.1:8875', screenshot: 'only-on-failure', trace: 'retain-on-failure' },
  projects: [
    { name: 'chromium-desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'chromium-mobile', use: { ...devices['Pixel 7'], defaultBrowserType: 'chromium' } }
  ],
  webServer: [{
    command: shellQuote(python) + ' tests/browser/portal_fixture.py',
    url: 'http://127.0.0.1:8875/connect',
    reuseExistingServer: false,
    timeout: 15000
  }, {
    command: shellQuote(python) + ' tests/browser/admin_fixture.py',
    url: 'https://127.0.0.1:8876/healthz',
    ignoreHTTPSErrors: true,
    reuseExistingServer: false,
    timeout: 15000
  }]
});

