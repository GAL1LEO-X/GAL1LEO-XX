const { test, expect } = require('@playwright/test');

test.beforeEach(async ({ page, request }) => {
  await request.post('/test/reset');
  await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
});

test('QR renews and stale credentials disappear after failure and connection', async ({ page, request }) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/connect');
  await expect(page.locator('#status')).toContainText('interrupted');
  await page.getByRole('button', { name: "Use the QR code", exact: true }).click();
  await expect(page.locator('#qr-image')).toBeVisible();
  const previous = (await (await request.get('/test/receipt')).json()).qr_reads;
  await request.post('/test/rotate');
  await expect.poll(async () => (await (await request.get('/test/receipt')).json()).qr_reads).toBeGreaterThan(previous);
  await request.post('/test/fail');
  await expect(page.locator('#qr-result')).toBeHidden();
  await expect(page.locator('#qr-image')).not.toHaveAttribute('src');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  await request.post('/test/fail');
  await expect(page.locator('#code-result')).toBeHidden();
  await expect(page.locator('#pairing-code')).toHaveText('');
  await page.getByRole('button', { name: "Use the QR code", exact: true }).click();
  await expect(page.locator('#qr-image')).toBeVisible();
  await request.post('/test/working');
  await expect(page.locator('#pairing')).toBeHidden();
  await expect(page.locator('#status')).toContainText('connected');
  expect(errors).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('wrong account is explained and retry retains the selected profile', async ({ page, request }) => {
  await request.post('/test/wrong-owner');
  await page.goto('/connect');
  await expect(page.getByRole('heading', { level: 1 })).toHaveText("Connect your WhatsApp.");
  await expect(page.locator('.identity')).toContainText('Demo profile · test account');
  await page.getByRole('link', { name: "Sign in and continue" }).click();
  await expect(page.getByRole('heading', { level: 1 })).toHaveText("Sign-in incomplete.");
  await expect(page.getByRole('alert')).toContainText('only its owner');
  await expect(page.locator('.identity')).toContainText("Sign-in required");
  await expect(page.locator('#pairing')).toHaveCount(0);
  await page.getByRole('link', { name: "Back to the start" }).click();
  await expect(page.getByRole('link', { name: "Sign in and continue" })).toBeVisible();
  await request.post('/test/correct-owner');
  await page.getByRole('link', { name: "Sign in and continue" }).click();
  await expect(page.locator('.identity')).toContainText("Access verified");
  await expect(page.locator('#pairing')).toBeVisible();
  expect((await (await request.get('/test/receipt')).json()).pairs).toBe(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('expired session clears credentials and provides an accessible login action', async ({ page, request }) => {
  await page.goto('/connect');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  await request.post('/test/expire');
  await expect(page.locator('#session-expired')).toBeVisible();
  await expect(page.locator('#pairing')).toBeHidden();
  await expect(page.locator('#pairing-code')).toBeEmpty();
  await expect(page.locator('#qr-image')).not.toHaveAttribute('src');
  await expect(page.locator('#session-actions')).toBeHidden();
  await page.getByRole('link', { name: "Sign in and continue" }).click();
  await expect(page.locator('#pairing')).toBeVisible();
  await expect(page.locator('#pairing-code')).toBeEmpty();
});

test('repeated actions submit once while pending and rate limits remain recoverable', async ({ page, request }) => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/connect/api/pair', async route => { await pending; await route.continue(); });
  await page.goto('/connect');
  await expect(page.locator('#qr-button')).toBeEnabled();
  await page.locator('#qr-button').evaluate(button => { button.click(); button.click(); });
  await expect(page.locator('#code-button')).toBeDisabled();
  await expect(page.locator('#qr-button')).toBeDisabled();
  await expect(page.locator('#pairing')).toHaveAttribute('aria-busy', 'true');
  release();
  await expect(page.locator('#qr-image')).toBeVisible();
  expect((await (await request.get('/test/receipt')).json()).pairs).toBe(1);
  await request.post('/test/reject-pair');
  await page.getByRole('button', { name: "Use the QR code", exact: true }).click();
  await expect(page.getByRole('alert')).toContainText("Wait 30 seconds");
  await expect(page.locator('#qr-result')).toBeHidden();
  await expect(page.locator('#qr-button')).toBeEnabled();
  await expect(page.getByRole('alert')).toBeFocused();
});

test('logout and browser history never revive a code or a signed-in page', async ({ page, request }) => {
  // A distinct entry avoids same-URL navigation replacing the current entry.
  await page.goto('/connect?history=fixture');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  // Record only a boolean from the departing document, never credentials, to
  // verify sanitization whether or not the browser chooses to use bfcache.
  await page.evaluate(() => {
    window.addEventListener('pagehide', () => sessionStorage.setItem('sanitized', String(
      document.getElementById('pairing-code').textContent === '' &&
      !document.getElementById('qr-image').hasAttribute('src') &&
      document.getElementById('phone').value === ''
    )));
  });
  await page.getByRole('button', { name: "Sign out of this page", exact: true }).click();
  await expect(page.getByRole('link', { name: "Sign in and continue" })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('sanitized'))).toBe('true');
  await page.goBack();
  await expect(page.getByRole('link', { name: "Sign in and continue" })).toBeVisible();
  await expect(page.locator('#pairing-code')).toHaveCount(0);
  expect((await (await request.get('/test/receipt')).json()).state).toBe('SCAN_QR_CODE');
});

test('an old status response cannot clear a newly requested pairing code', async ({ page }) => {
  let release, captured;
  const delayed = new Promise(resolve => { release = resolve; });
  const started = new Promise(resolve => { captured = resolve; });
  await page.goto('/connect');
  await expect(page.locator('#qr-button')).toBeEnabled();
  await page.route('**/connect/api/status', async route => {
    captured();
    await delayed;
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({state: 'FAILED', connected: false}) });
  });
  await started;
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  const completed = page.waitForResponse('**/connect/api/status');
  release();
  await completed;
  await page.unroute('**/connect/api/status');
  await expect(page.locator('#code-result')).toBeVisible();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
});

test('all page states fit narrow screens and retain usable controls', async ({ page, request }, testInfo) => {
  const path = require('node:path');
  const fs = require('node:fs');
  const screenshots = process.env.PLUGINS_SCREENSHOT_DIR;
  async function capture(name) {
    await page.evaluate(() => window.scrollTo(0, 0));
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (screenshots) {
      fs.mkdirSync(screenshots, { recursive: true });
      await page.screenshot({ path: path.join(screenshots, `${testInfo.project.name}-${name}.png`), fullPage: true });
    }
  }
  await request.post('/test/expire');
  await page.goto('/connect');
  await capture('login');
  await page.getByRole('link', { name: "Sign in and continue" }).click();
  await expect(page.locator('#pairing')).toBeVisible();
  await capture('connect');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  await capture('code');
  await request.post('/test/working');
  await expect(page.locator('#connected')).toBeVisible();
  await capture('confirmation');
  await request.post('/test/wrong-owner');
  await page.goto('/connect/login');
  await expect(page.getByRole('alert')).toBeVisible();
  await capture('wrong-account');
  await page.setViewportSize({width: 320, height: 640});
  await capture('narrow-error');
});


test('status retry sends one request and clears the recovered service error', async ({ page }) => {
  let reads = 0, release;
  const pending = new Promise(resolve => { release = resolve; });
  await page.route('**/connect/api/status', async route => {
    reads++;
    if (reads === 1) return route.fulfill({status: 503, contentType: 'application/json', body: JSON.stringify({error: 'Service temporarily unreachable.'})});
    await pending;
    await route.continue();
  });
  await page.goto('/connect');
  await expect(page.getByRole('alert')).toContainText('temporarily');
  await expect(page.locator('#status-retry')).toBeEnabled();
  await page.locator('#status-retry').evaluate(button => { button.click(); button.click(); });
  await expect(page.locator('#status-retry')).toBeDisabled();
  await expect.poll(() => reads).toBe(2);
  release();
  await expect(page.locator('#pairing')).toBeVisible();
  await expect(page.getByRole('alert')).toBeHidden();
  expect(reads).toBe(2);
});

test('lost pairing response never triggers an automatic second request', async ({ page, request }) => {
  await page.route('**/connect/api/pair', async route => {
    await route.fetch(); // The synthetic server accepted it, but the response is lost.
    await route.abort('failed');
  }, { times: 1 });
  await page.goto('/connect');
  await page.getByRole('button', { name: "Use the QR code", exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Check your connection');
  await expect(page.locator('#qr-result')).toBeHidden();
  await expect(page.locator('#status')).toContainText('Waiting for the phone');
  expect((await (await request.get('/test/receipt')).json()).pairs).toBe(1);
  await request.post('/test/reject-pair');
  await page.getByRole('button', { name: "Use the QR code", exact: true }).click();
  await expect(page.getByRole('alert')).toContainText("Wait 30 seconds");
  expect((await (await request.get('/test/receipt')).json()).pairs).toBe(2);
  await expect(page.locator('#qr-button')).toBeEnabled();
});

for (const connected of [false, true]) test(`lost logout response does not restore the closed session (connected=${connected})`, async ({ page, request }) => {
  await page.goto('/connect');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button', { name: "Generate temporary code", exact: true }).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  if (connected) {
    await request.post('/test/working');
    await expect(page.locator('#connected')).toBeVisible();
  }
  await page.route('**/connect/api/logout', async route => { await route.fetch(); await route.abort('failed'); });
  await page.getByRole('button', { name: "Sign out of this page", exact: true }).click();
  await expect(page.locator('#pairing-code')).toBeEmpty();
  await expect(page.locator('#session-expired')).toBeVisible();
  await expect(page.locator('.identity')).toContainText("Sign-in required");
  await expect(page.getByRole('link', { name: "Sign in and continue" })).toBeVisible();
  await expect(page.locator('#pairing')).toBeHidden();
});
