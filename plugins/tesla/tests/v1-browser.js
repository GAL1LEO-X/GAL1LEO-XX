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
  const errors = [];
  let external = 0;
  page.on('pageerror', error => errors.push(error.message));
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
    await expect(page.locator('.charge-value')).toContainText("Unavailable");
    await expect(page.locator('.charge-summary')).toContainText("Invalid value");
    await expect(page.locator('.vehicle-metrics')).toContainText("Historical · 10 min ago");
    const battery = page.locator('.charge-summary > .metric-evidence');
    await battery.locator(':scope > summary').focus();
    await page.keyboard.press('Enter');
    await expect(battery).toHaveAttribute('open', '');
    await expect(battery).toContainText("Last valid value · historical: 66 %");
    await expect(battery).toContainText('Fleet Telemetry');
    await page.locator('.route-panel > summary').click();
    await expect(page.locator('.route-sketch')).toBeVisible();
    await expect(page.locator('.route-panel')).toContainText('It does not prove the complete route');
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if ([390, 1440].includes(width)) await capture(`v1-evidence-route-${width}`);
    }
    await page.clock.fastForward(135000);
    await expect(page.locator('.vehicle-metric').first().locator('.observation')).toContainText("Historical · 2 min ago");
    await page.getByRole('navigation').getByRole('link', {name: "Data collection", exact: true}).click();
    await page.getByLabel("Collection duration", {exact: true}).selectOption('3600');
    await expect(page.locator('#temporary-estimate')).toContainText("1 hour");
    await expect(page.locator('#temporary-estimate')).toContainText('not a spending cap');
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();
    await expect(page.locator('#collection-duration')).toHaveValue('3600');
    await page.getByRole('button', {name: "Review configuration", exact: true}).click();
    await expect(page.locator('.temporary-collection')).toContainText("60 minutes");
    await expect(page.locator('.temporary-collection')).toContainText('authorizes startup, verification reads and this restoration');
    await page.getByText("Exact profile to restore", {exact: true}).click();
    await expect(page.locator('.temporary-collection')).toContainText('Included fields: Locked');
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if ([390, 1440].includes(width)) await capture(`v1-temporary-review-${width}`);
    }
    await page.getByRole('button', {name: "Confirm collection", exact: true}).click();
    await expect(page.locator('.temporary-collection')).toContainText("application needs verification");
    await expect(page.locator('.temporary-collection')).toContainText("Expected deadline");
    await expect(page.getByRole('button', {name: "Confirm collection", exact: true})).toHaveCount(0);
    await capture('v1-temporary-accepted');
    expect(errors).toEqual([]);
    console.log(JSON.stringify({external_requests: external, evidence_reviewed: true, temporary_reviewed: true}));
  } finally {await browser.close();}
})().catch(error => {console.error(error); process.exitCode = 1;});
