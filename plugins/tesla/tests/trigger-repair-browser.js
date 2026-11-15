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
  page.on('pageerror', e => errors.push(e.message));
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin !== config.origin) {
      external++;
      return route.abort();
    }
    return route.continue();
  });
  try {
    await page.goto(config.origin+'/tesla/owner');
    await page.getByLabel("Panel passphrase").fill('synthetic-owner-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await page.goto(config.origin+'/tesla/owner/triggers/'+config.vehicle_ref);
    await page.getByRole('button', {name: "Use recommended", exact: true}).click();
    const selected = await page.locator('input[name="enabled"]:checked').evaluateAll(nodes => nodes.map(n => n.value));
    await expect(page.locator('.other-events .trigger-item').first()).toBeHidden();
    // Native HTML submission includes checked inputs in closed disclosures.
    await page.locator('.trigger-group').first().getByRole('button', {name: "Save selection", exact: true}).click();
    expect(await page.locator('input[name="enabled"]:checked').evaluateAll(nodes => nodes.map(n => n.value))).toEqual(selected);
    const battery = page.locator('[data-trigger="event:battery_low"]');
    await battery.locator('.trigger-evidence > summary').click();
    await expect(battery).toContainText("Missing fields: Battery level");
    await battery.getByRole('link').click();
    await expect(page.locator('#trigger-proposal')).toContainText('Previous estimate:');
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(2);
    await expect(page.locator('[data-field="InsideTemp"] .interval')).toHaveValue('600');
    expect(await page.locator('[name="trigger_revision"]').inputValue()).toBe('2');
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();
    expect(await page.locator('[name="trigger_revision"]').inputValue()).toBe('2');
    for (const width of [320, 390, 1440]) {
      await page.setViewportSize({width, height: 950});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (config.results && width !== 320) {
        fs.mkdirSync(config.results, {recursive: true});
        await page.evaluate(() => {document.activeElement.blur(); window.scrollTo(0, 0);});
        await page.screenshot({path: path.join(config.results, `trigger-repair-${width}.png`), fullPage: true});
      }
    }
    expect(errors).toEqual([]);
    console.log(JSON.stringify({repair_draft: true, selection_preserved: true, external_requests: external}));
  } finally { await browser.close(); }
})().catch(error => {console.error(error); process.exitCode = 1;});
