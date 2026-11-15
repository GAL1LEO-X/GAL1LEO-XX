const {chromium, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const config = JSON.parse(process.argv[2]);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox',
    `--host-resolver-rules=MAP tesla.localhost:443 127.0.0.1:${config.port}`]});
  const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1440, height: 1000}});
  const page = await context.newPage();
  await page.clock.install();
  let external = 0, requests = 0;
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', () => requests++);
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin !== config.origin) {external++; return route.abort();}
    return route.continue();
  });
  async function capture(name) {
    if (!config.results) return;
    await page.evaluate(() => {document.activeElement.blur(); window.scrollTo(0, 0);});
    fs.mkdirSync(config.results, {recursive: true});
    await page.screenshot({path: path.join(config.results, name+'.png'), fullPage: true});
  }
  try {
    await page.goto(config.origin+'/tesla/owner');
    await page.getByLabel("Panel passphrase").fill('synthetic-owner-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await page.locator('.park-panel > summary').click();
    await page.locator('.route-panel > summary').click();
    await page.locator('.history-panel > summary').click();
    await capture('audit-00-rendered-desktop');
    await expect(page.locator('.history-panel')).toContainText('50–90 %');
    await expect(page.locator('.park-panel > summary')).toContainText("Park observed");
    await expect(page.locator('.park-panel [data-evidence-expired]').first()).not.toBeVisible();
    await expect(page.locator('.route-sketch')).toBeVisible();
    await capture('audit-01-current-desktop');
    const before = requests;
    await page.clock.fastForward(16000);
    await expect(page.locator('.park-panel > summary')).toContainText("Assessment expired");
    await expect(page.locator('.park-panel > summary [data-evidence-current]')).not.toBeVisible();
    await expect(page.locator('.park-panel .operating-context')).not.toBeVisible();
    await expect(page.locator('.route-sketch')).toBeVisible();
    await page.clock.fastForward(315000);
    await expect(page.locator('.route-sketch')).not.toBeVisible();
    await expect(page.locator('.route-panel')).toContainText("Current geometry unavailable");
    await expect(page.locator('.route-panel > summary [data-evidence-current]')).not.toBeVisible();
    await expect(page.locator('.route-panel')).not.toContainText("Age: 0 s");
    const agingRequests = requests-before;
    for (const width of [1440, 390]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await capture(`audit-02-expired-${width}`);
    }
    await page.getByRole('navigation').getByRole('link', {name: "Data collection", exact: true}).click();
    const editor = page.locator('#collection-editor');
    await editor.locator('[name="revision"]').evaluate(input => {input.value = 'stale-draft-revision';});
    const batteryField = editor.locator('[data-field="BatteryLevel"]');
    await batteryField.locator('details > summary').click();
    await batteryField.locator('[name="interval_BatteryLevel"]').fill('75');
    await batteryField.locator('[name="resend_BatteryLevel"]').fill('150');
    const [response] = await Promise.all([
      page.waitForResponse(r => r.request().method() === 'POST' && r.url().includes('/owner/collection/')),
      page.getByRole('button', {name: "Calculate estimate", exact: true}).click()
    ]);
    expect(response.status()).toBe(409);
    await expect(page.getByRole('alert')).toContainText('Entered values are retained');
    await expect(page.locator('#collection-editor [name="revision"]')).toHaveValue('stale-draft-revision');
    await expect(page.locator('#collection-editor [name="interval_BatteryLevel"]')).toHaveValue('75');
    await expect(page.getByRole('button', {name: "Review configuration", exact: true})).toBeDisabled();
    await capture('audit-03-stale-draft-mobile');
    expect(errors).toEqual([]);
    console.log(JSON.stringify({external_requests: external, requests_during_aging: agingRequests,
      park_expired: true, route_expired: true}));
  } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode = 1;});
