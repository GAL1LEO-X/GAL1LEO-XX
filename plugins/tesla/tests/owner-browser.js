const {chromium, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const config = JSON.parse(process.argv[2]);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox',
    `--host-resolver-rules=MAP tesla.localhost:443 127.0.0.1:${config.port}`]});
  const context = await browser.newContext({ignoreHTTPSErrors: true, viewport: {width: 1440, height: 1000}});
  const page = await context.newPage();
  const errors = [];
  let external = 0;
  page.on('pageerror', error => errors.push(error.message));
  page.on('requestfailed', request => errors.push(request.failure()?.errorText));
  // The local test certificate is ephemeral. DNS maps only tesla.localhost to
  // the random loopback port; redirects, HTTPS cookies and forms remain native.
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== config.origin) {
      external++;
      await route.abort();
      return;
    }
    await route.continue();
  });
  try {
    await page.goto(config.origin+'/tesla/owner');
    await expect(page.getByRole('heading', {name: "Sign in", exact: true})).toBeVisible();
    if (config.results) {
      fs.mkdirSync(config.results, {recursive: true});
      await page.screenshot({path: path.join(config.results, 'owner-login.png'), fullPage: true});
    }
    await page.getByLabel("Panel passphrase").fill('synthetic-incorrect-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await expect(page.getByRole('alert')).toHaveText("Invalid passphrase. Try again.");
    await expect(page.getByLabel("Panel passphrase")).toHaveAttribute('aria-invalid', 'true');
    await page.getByLabel("Panel passphrase").fill('synthetic-owner-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await expect(page.getByRole('heading', {name: 'the vehicle', exact: true})).toBeVisible();
    await page.waitForLoadState('load');
    await expect(page.locator('.park-panel')).not.toHaveAttribute('open', '');
    await expect(page.locator('.park-panel > summary')).toContainText("Park cannot be verified");
    await page.locator('.park-panel > summary').click();
    await expect(page.locator('.park-panel')).toContainText('This is historical data');
    await expect(page.locator('.park-panel')).toContainText("invalid-value marker");
    await page.locator('.park-panel > summary').click();
    await expect(page.locator('.history-panel')).not.toHaveAttribute('open', '');
    await page.locator('.history-panel > summary').click();
    await expect(page.getByRole('img', {name: /Battery observations/})).toHaveCount(1);
    await expect(page.getByRole('img', {name: /Battery observations/})).toBeVisible();
    await page.locator('.history-panel > summary').click();
    const cookie = (await context.cookies()).find(c => c.name === '__Secure-tesla-owner');
    expect(cookie?.secure && cookie?.httpOnly && cookie?.sameSite === 'Lax').toBe(true);
    const illustration = page.getByRole('img', {name: "Illustration of a black Model Y Legacy Performance"});
    await expect(illustration).toBeVisible();
    await expect.poll(() => illustration.evaluate(img => img.complete && img.naturalWidth > 0)).toBe(true);
    await expect(page.getByText("Charging", {exact: true})).toBeVisible();
    await expect(page.getByRole('button', {name: "Disconnect and delete local data"})).toBeHidden();
    // Navigation must remain reachable after an anchor jump, without the
    // browser test implicitly scrolling it into view before a click.
    for (const width of [1440, 390, 320]) {
      await page.setViewportSize({width, height: 900});
      for (const [label, heading] of [["Data collection", "Data collection"], ["Events", "Events for ChatGPT"]]) {
        await page.getByRole('navigation').getByRole('link', {name: label, exact: true}).click();
        await expect(page.getByRole('heading', {name: heading, exact: true})).toBeVisible();
        await expect(page.getByRole('navigation').getByRole('link', {name: label, exact: true})).toHaveAttribute('aria-current', 'page');
        await page.getByRole('navigation').getByRole('link', {name: "Overview", exact: true}).click();
        await expect(page.getByRole('heading', {name: 'the vehicle', exact: true})).toBeVisible();
      }
      for (const label of ["Activity", "Connection"]) {
        await page.getByRole('navigation').getByRole('link', {name: label, exact: true}).click();
        expect(await page.evaluate(() => scrollY)).toBeGreaterThan(0);
        await expect(page.getByRole('navigation')).toBeInViewport({ratio: 1});
        const header = await page.locator('.site-header').boundingBox();
        expect(header.y).toBe(0);
        await expect(page.getByRole('link', {name: "Back to the top of the page"})).toBeInViewport({ratio: 1});
        await page.getByRole('link', {name: "Back to the top of the page"}).click();
        expect(await page.evaluate(() => scrollY)).toBe(0);
      }
    }
    await page.setViewportSize({width: 1440, height: 1000});
    if (config.results) {
      fs.mkdirSync(config.results, {recursive: true});
      await page.screenshot({path: path.join(config.results, 'owner-desktop.png'), fullPage: true});
      await page.screenshot({path: path.join(config.results, 'owner-overview.png'), fullPage: false});
    }
    await page.setViewportSize({width: 390, height: 844});
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (config.results) await page.screenshot({path: path.join(config.results, 'owner-mobile.png'), fullPage: true});
    for (const width of [320, 768]) {
      await page.setViewportSize({width, height: 900});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await expect(illustration).toBeVisible();
      await page.locator('.history-panel > summary').click();
      await expect(page.getByRole('img', {name: /Battery observations/})).toHaveCount(1);
      const chart = await page.getByRole('img', {name: /Battery observations/}).boundingBox();
      expect(chart.x >= 0 && chart.x + chart.width <= width).toBe(true);
      expect(chart.height).toBeLessThanOrEqual(160);
      await page.locator('.history-panel > summary').click();
    }
    await page.setViewportSize({width: 390, height: 844});
    await page.locator('.connection-panel details').evaluate(el => el.open = false);
    await page.locator('.connection-panel summary').click();
    await expect(page.getByRole('button', {name: "Disconnect and delete local data"})).toBeVisible();
    await page.getByRole('link', {name: "Manage events · the vehicle"}).click();
    await expect(page.getByRole('heading', {name: "Events for ChatGPT", exact: true})).toBeVisible();
    const climate = page.locator('.trigger-group').filter({has: page.locator('summary > span', {hasText: /^Climate$/})});
    await page.locator('.advanced-settings > summary').click();
    await climate.locator('summary').first().click();
    await climate.getByRole('checkbox', {name: /^Cabin temperature/}).check();
    await climate.getByRole('button', {name: "Save selection", exact: true}).click();
    await expect(page.getByRole('status')).toContainText('Selection saved');
    await page.locator('.advanced-settings > summary').click();
    await climate.locator('summary').first().click();
    await expect(climate.getByRole('checkbox', {name: /^Cabin temperature/})).toBeChecked();
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 900});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (config.results && [390, 1440].includes(width)) {
        await page.screenshot({path: path.join(config.results, `owner-triggers-${width}.png`), fullPage: true});
      }
    }
    await climate.getByRole('button', {name: "Disable category", exact: true}).click();
    await page.locator('.advanced-settings > summary').click();
    await climate.locator('summary').first().click();
    await expect(climate.getByRole('checkbox', {name: /^Cabin temperature/})).not.toBeChecked();
    await page.setViewportSize({width: 390, height: 844});
    await page.goto(config.origin+'/tesla/owner/intents/'+config.execute);
    await expect(page.getByText("Status: Awaiting confirmation", {exact: true})).toBeVisible();
    await expect(page.getByText("Charge limit", {exact: true})).toBeVisible();
    await expect(page.locator('.parameters dd')).toHaveText('80 %');
    if (config.results) await page.screenshot({path: path.join(config.results, 'owner-confirmation-mobile.png'), fullPage: true});
    await page.getByRole('button', {name: "Confirm and execute"}).click();
    await expect(page.getByText(/Status: Accepted by Tesla/)).toBeVisible();
    await page.reload();
    await expect(page.getByRole('button', {name: "Confirm and execute"})).toHaveCount(0);
    await page.goto(config.origin+'/tesla/owner/intents/'+config.cancel);
    await page.getByRole('button', {name: "Cancel", exact: true}).click();
    await expect(page.getByText("Status: Cancelled", {exact: true})).toBeVisible();
    await page.goto(config.origin+'/tesla/owner');
    await page.getByRole('button', {name: "Sign out", exact: true}).click();
    await expect(page.getByRole('heading', {name: "Sign in", exact: true})).toBeVisible();
    expect(errors).toEqual([]);
    expect(external).toBe(0);
    console.log(JSON.stringify({synthetic_only: true, desktop: true, mobile: true, external_requests: external}));
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
