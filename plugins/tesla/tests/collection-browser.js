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
  await context.route('**/*', async route => {
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
    await page.getByRole('navigation').getByRole('link', {name: "Data collection", exact: true}).click();
    await expect(page.getByRole('heading', {name: "Data collection", exact: true})).toBeVisible();
    await expect(page.locator('#selected-count')).toHaveText('7');
    await expect(page.getByRole('heading', {name: "Essential automatic collection"})).toBeVisible();
    if (config.results) {
      fs.mkdirSync(config.results, {recursive: true});
      await page.locator('.preset-section').screenshot({path: path.join(config.results, 'collection-presets.png')});
    }
    await expect(page.locator('.collection-guidance')).toContainText('does not guarantee an exact cadence');
    for (const [preset, total] of [['charging', 9], ['comfort', 8], ['drive_diagnostics', 7]]) {
      await page.getByLabel("Other presets").selectOption(preset);
      await page.getByRole('button', {name: "Load into form"}).click();
      await expect(page.locator('#selected-count')).toHaveText(String(total));
      await expect(page.locator('#proposal-name')).not.toContainText("Custom");
      await expect(page.locator('.proposal-label')).toContainText("Changes awaiting confirmation");
      await page.locator('.profile-picker > summary').click();
    }
    await page.getByLabel("Other presets").selectOption('essential');
    await page.getByRole('button', {name: "Load into form"}).click();
    await expect(page.locator('#selected-count')).toHaveText('4');
    await expect(page.getByLabel("Other presets")).toHaveValue('essential');
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(4);
    const initialRow = page.locator('[data-field="BatteryLevel"]');
    await expect(initialRow.locator('.field-description')).toContainText('Battery state of charge percentage');
    await expect(initialRow.locator('.field-frequency')).toContainText("every 1 minute");
    await expect(initialRow.locator('.field-frequency')).toContainText("Requested resend: 15 minutes");
    await page.locator('.collection-tempo > summary').click();
    const initialCost = await page.locator('#monthly-cost').innerText();
    await page.getByRole('button', {name: "Less frequent · intervals ×2", exact: true}).click();
    await expect(initialRow.locator('.field-frequency')).toContainText("every 2 minutes");
    await expect(initialRow.locator('.field-frequency')).toContainText("Requested resend: 30 minutes");
    expect(Number((await page.locator('#monthly-cost').innerText()).replace(',', '.'))).toBeLessThan(Number(initialCost.replace(',', '.')));
    await page.getByRole('button', {name: "Restore loaded timing", exact: true}).click();
    await expect(page.locator('#monthly-cost')).toHaveText(initialCost);
    await page.getByRole('button', {name: "More frequent · intervals ÷2", exact: true}).click();
    await expect(initialRow.locator('.interval')).toHaveValue('30');
    await expect(initialRow.locator('.resend')).toHaveValue('450');
    await page.getByRole('button', {name: "Restore loaded timing", exact: true}).click();
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (config.results && [390, 1440].includes(width))
        await page.locator('.collection-selected').screenshot({path: path.join(config.results, `selected-${width}.png`)});
    }
    await page.locator('.collection-catalog > summary').click();
    for (const [field, reason] of [['AccessoryRail', 'update the receiver'], ['TonneauPosition', 'limited'], ['LifetimeEnergyUsedDrive', 'limited']]) {
      await page.getByLabel("Search fields").fill(field);
      const unavailable = page.locator(`[data-field="${field}"]`);
      await expect(unavailable.getByRole('checkbox')).toBeDisabled();
      await expect(unavailable).toContainText(reason);
      await expect(page.locator('#catalog-search-status')).not.toContainText("available data");
    }
    await page.getByLabel("Search fields").fill('temperature');
    const temperature = page.locator('[data-field="InsideTemp"]');
    await temperature.getByRole('checkbox').check();
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(5);
    await expect(page.locator('[name="field"][value="InsideTemp"]')).toHaveCount(1);
    await temperature.getByRole('checkbox').uncheck();
    await page.getByLabel("Search fields").fill('');
    await page.getByRole('button', {name: "Select all", exact: true}).click();
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(234);
    const fullCost = await page.locator('#monthly-cost').innerText();
    await page.getByLabel("Search selected fields").fill('BatteryLevel');
    await expect(page.locator('#selected-fields > .collection-field:visible')).toHaveCount(1);
    await expect(page.locator('#selected-count')).toHaveText('234');
    await expect(page.locator('#monthly-cost')).toHaveText(fullCost);
    await page.getByLabel("Search selected fields").fill('');
    const selectedNames = await page.locator('#collection-editor').evaluate(form => new FormData(form).getAll('field'));
    expect(new Set(selectedNames).size).toBe(234);
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();
    await expect(page.locator('#selected-count')).toHaveText('234');
    await expect(page.locator('#monthly-cost')).toHaveText(fullCost);
    await expect(page.locator('[data-field="Gear"] .field-evidence')).toContainText("no archived sample");
    await page.locator('.collection-catalog > summary').click();
    await page.getByRole('button', {name: "Deselect all", exact: true}).click();
    await expect(page.locator('#monthly-cost')).toHaveText('0.00');
    await expect(page.getByRole('button', {name: "Review configuration"})).toBeDisabled();
    await page.locator('.collection-category[data-category="Charging"] > summary').click();
    const row = page.locator('[data-field="BatteryLevel"]');
    await row.getByRole('checkbox').check();
    await row.locator('.field-customize > summary').click();
    await page.getByLabel("Hours per day with an awake vehicle").fill('20');
    await row.locator('.interval').fill('30');
    await row.locator('.resend').fill('300');
    await expect(page.locator('#monthly-cost')).toHaveText('0.53');
    await expect(page.locator('#selected-count')).toHaveText('1');
    await expect(page.locator('#selected-fields > .collection-field')).toHaveCount(1);
    await row.locator('.resend').fill('10');
    await expect(page.locator('#monthly-cost')).toHaveText('—');
    await expect(page.getByRole('button', {name: "Review configuration"})).toBeDisabled();
    await row.locator('.resend').fill('300');
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();
    await expect(page.locator('#monthly-cost')).toHaveText('0.53');
    await expect(page.locator('#selected-count')).toHaveText('1');
    await expect(row.locator('.interval')).not.toBeVisible();
    await expect(row.locator('.field-frequency')).toContainText("every 30 seconds");
    await expect(row.locator('.field-frequency')).toContainText("Requested resend: 5 minutes");
    await row.locator('.field-customize > summary').click();
    await row.locator('.delta').fill('0.5');
    await row.locator('.includes').fill('Locked, InsideTemp');
    await expect(page.locator('#monthly-cost')).toHaveText('1.58');
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();
    await expect(page.locator('#monthly-cost')).toHaveText('1.58');
    await row.locator('.field-customize > summary').click();
    await expect(row.locator('.delta')).toHaveValue('0.5');
    await expect(row.locator('.includes')).toHaveValue('Locked, InsideTemp');
    await row.locator('.includes').fill('');
    await page.getByRole('button', {name: "Calculate estimate", exact: true}).click();

    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await expect(page.getByRole('navigation')).toBeInViewport({ratio: 1});
      if (config.results && [390, 1440].includes(width)) {
        fs.mkdirSync(config.results, {recursive: true});
        await page.evaluate(() => {document.activeElement.blur(); window.scrollTo(0, 0);});
        await page.screenshot({path: path.join(config.results, `collection-${width}.png`), fullPage: true});
      }
    }
    await page.getByRole('button', {name: "Review configuration"}).click();
    await expect(page.getByRole('heading', {name: "Configure data collection"})).toBeVisible();
    await expect(page.locator('.parameters')).toContainText('0.53 USD');
    await expect(page.locator('.parameters')).toContainText("20 hours/day");
    await page.getByRole('button', {name: "Cancel", exact: true}).click();
    await expect(page.getByText("Status: Cancelled", {exact: true})).toBeVisible();
    await page.getByRole('link', {name: "← Back to data collection"}).click();
    await expect(page.getByRole('button', {name: "Review configuration"})).toBeEnabled();
    await page.goto(config.origin+'/tesla/owner');
    await page.getByRole('link', {name: /^Manage events/}).click();
    await page.getByRole('button', {name: "Use recommended", exact: true}).click();
    await expect(page.getByText('Selection saved.', {exact: false})).toBeVisible();
    const main = page.locator('.trigger-group').filter({has: page.locator('summary', {hasText: "Primary events"})});
    await expect(main.locator('input:checked')).toHaveCount(7);
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({width, height: 1000});
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      if (config.results && width === 1440)
        await page.locator('.preset-section').screenshot({path: path.join(config.results, 'event-presets.png')});
    }
    const battery = page.locator('.rule-settings details').filter({has: page.locator('summary', {hasText: "Battery · threshold"})});
    await page.locator('.advanced-settings > summary').click();
    await battery.locator('summary').click();
    await battery.getByLabel("Threshold", {exact: true}).fill('25');
    await battery.getByRole('button', {name: "Save condition"}).click();
    await page.locator('.advanced-settings > summary').click();
    await battery.locator('summary').click();
    await expect(battery.getByLabel("Threshold", {exact: true})).toHaveValue('25.0');
    await page.getByRole('button', {name: "Use none", exact: true}).click();
    await expect(page.locator('.trigger-group input:checked')).toHaveCount(0);
    expect(errors).toEqual([]);
    expect(external).toBe(0);
    console.log(JSON.stringify({calculator: true, owner_review: true, external_requests: external}));
  } finally { await browser.close(); }
})().catch(e => {console.error(e); process.exitCode = 1;});
