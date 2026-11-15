const {chromium, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
  const config = JSON.parse(process.argv[2]);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox',
    `--host-resolver-rules=MAP tesla.localhost:443 127.0.0.1:${config.port}`]});
  const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1440, height: 1000}});
  const page = await context.newPage();
  let external = 0;
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin !== config.origin) {external++; return route.abort();}
    return route.continue();
  });
  async function capture(name) {
    await page.evaluate(() => {document.activeElement.blur(); window.scrollTo(0, 0);});
    if (config.results) {
      fs.mkdirSync(config.results, {recursive: true});
      await page.screenshot({path: path.join(config.results, name+'.png'), fullPage: true});
      await page.screenshot({path: path.join(config.results, name+'-viewport.png')});
    }
  }
  try {
    await page.goto(config.origin+'/tesla/owner');
    await page.getByLabel("Panel passphrase").fill('synthetic-owner-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await expect(page.locator('.console-overview')).toContainText('7 fields in the verified profile');
    await expect(page.locator('.console-overview')).toContainText("17 events and 239 changes selected");
    await expect(page.locator('.vehicle-heading h1')).toBeVisible();
    await expect(page.locator('.layout-dashboard .page-heading')).toHaveCount(0);
    await expect(page.locator('.vehicle-visual figcaption')).toHaveCount(0);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 844});
      await expect(page.locator('.vehicle-visual img')).toBeInViewport({ratio: 1});
      for (const selector of ['.history-panel', '.events-panel', '.actions-panel']) {
        await expect(page.locator(selector)).not.toHaveAttribute('open', '');
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await page.setViewportSize({width: 390, height: 844});
    await capture('workspace-overview-mobile');
    await page.setViewportSize({width: 1440, height: 1000});
    expect(await page.locator('.layout-dashboard main').evaluate(el => el.offsetHeight)).toBeLessThan(1000);
    await capture('workspace-overview');
    await expect(page.locator('.park-panel')).toHaveCount(1);
    await page.locator('.park-panel > summary').click();
    await expect(page.locator('.operating-context')).toBeVisible();
    await page.locator('.operating-signals > summary').click();
    await expect(page.locator('.operating-signals')).toContainText('DriveRail');
    await expect(page.locator('.operating-signals')).toContainText("No samples");
    await expect(page.locator('.operating-signals')).not.toContainText('missing');
    await expect(page.locator('.vehicle-metrics')).toContainText("Locks");
    await expect(page.locator('.vehicle-metrics')).toContainText("Locked");
    for (const width of [390, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await capture(`workspace-gear-${width}`);
    }
    await page.locator('.park-panel > summary').click();

    await page.locator('.actions-panel > summary').click();
    await expect(page.locator('.intent-list li')).toHaveCount(30);
    expect((await page.locator('.intent-list').boundingBox()).height).toBeLessThanOrEqual(320);
    await page.locator('.actions-panel > summary').click();
    await page.locator('.events-panel > summary').click();
    await expect(page.locator('.event-list li')).toHaveCount(12);
    expect((await page.locator('.event-list').boundingBox()).height).toBeLessThanOrEqual(320);
    await page.locator('.events-panel > summary').click();
    await page.getByRole('navigation').getByRole('link', {name: "Data collection", exact: true}).click();
    await expect(page.locator('.collection-status')).toContainText("Configuration applied");
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(7);
    await expect(page.locator('.profile-picker')).not.toHaveAttribute('open', '');
    await expect(page.locator('#trigger-impact .impact-details li').first()).toBeHidden();
    await page.locator('.collection-selected').scrollIntoViewIfNeeded();
    await expect(page.locator('#monthly-cost')).toBeInViewport();
    const data = await page.locator('.collection-choices').boundingBox();
    const cost = await page.locator('.collection-decision').boundingBox();
    expect(cost.x).toBeGreaterThan(data.x + data.width);
    await capture('workspace-collection-1440');
    await page.setViewportSize({width: 390, height: 844});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.locator('.collection-live-cost a').click();
    await expect(page.locator('#monthly-cost')).toBeInViewport();
    await page.getByRole('link', {name: "Back to the top of the page"}).click();
    expect(await page.evaluate(() => scrollY)).toBe(0);
    await capture('workspace-collection-390');
    await page.setViewportSize({width: 1440, height: 1000});
    await page.getByRole('navigation').getByRole('link', {name: "Events", exact: true}).click();
    await expect(page.locator('.trigger-connection')).toContainText("Connect ChatGPT event delivery");
    await expect(page.locator('.advanced-settings')).not.toHaveAttribute('open', '');
    await expect(page.getByRole('link', {name: 'Review data and cost for primary events →', exact: true})).toBeVisible();
    await capture('workspace-events-1440');
    for (const width of [320, 390, 768]) {
      await page.setViewportSize({width, height: 844});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await expect(page.getByRole('navigation')).toBeInViewport();
    }
    await page.locator('.connection-setup > summary').click();
    await expect(page.locator('#event-setup-prompt')).toHaveValue(/delivery_connection.subscription_plan/);
    await expect(page.locator('#event-setup-prompt')).toHaveAttribute('readonly', '');
    await page.getByRole('button', {name: "Copy request", exact: true}).click();
    await expect(page.locator('#event-setup-prompt-status')).toHaveText(/Copiato|Testo selezionato/);
    expect(errors).toEqual([]);
    console.log(JSON.stringify({external_requests: external, settings_unchanged: true}));
  } finally {await browser.close();}
})().catch(e => {console.error(e); process.exitCode = 1;});
