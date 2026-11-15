const {chromium, expect} = require('@playwright/test');

(async () => {
  const config = JSON.parse(process.argv[2]);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox',
    `--host-resolver-rules=MAP tesla.localhost:443 127.0.0.1:${config.port}, MAP auth.tesla.localhost:443 127.0.0.1:${config.port}, MAP * ~NOTFOUND`]});
  const context = await browser.newContext({ignoreHTTPSErrors: true});
  const page = await context.newPage();
  let syntheticOAuthPages = 0;
  let external = 0;
  const violations = [];
  const network = [];
  page.on('requestfailed', request => network.push({failed: new URL(request.url()).origin+new URL(request.url()).pathname,
    error: request.failure()?.errorText}));
  page.on('console', message => {
    if (message.text().includes('form-action')) violations.push(message.text());
  });
  page.on('response', response => {
    network.push({response: new URL(response.url()).origin+new URL(response.url()).pathname, status: response.status(),
      csp: response.headers()['content-security-policy']});
    if (new URL(response.url()).origin === 'https://auth.tesla.localhost' && response.status() === 200) syntheticOAuthPages++;
  });
  // Both allowed origins resolve only to the synthetic loopback server; all
  // other DNS fails. Redirects retain browser-native CSP enforcement.
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin === config.origin) return route.continue();
    if (url.origin === 'https://auth.tesla.localhost' && url.pathname === '/oauth2/v3/authorize') return route.continue();
    external++;
    return route.abort();
  });
  try {
    const login = await page.goto(config.origin+'/tesla/owner');
    expect(login.headers()['content-security-policy']).toContain("form-action 'self';");
    await page.getByLabel("Panel passphrase").fill('synthetic-owner-passphrase');
    await page.getByRole('button', {name: "Sign in", exact: true}).click();
    await expect(page.locator('.connection-panel > details > summary')).toContainText("Account connection required");
    await page.getByRole('button', {name: "Connect Tesla account", exact: true}).first().click();
    await expect(page.getByRole('heading', {name: 'Autorizzazione Tesla simulata'}),
      'OAuth navigation blocked: '+violations.join('\n')).toBeVisible();
    expect(violations).toEqual([]);
    await page.goto(config.origin+'/tesla/owner');
    // A hostname that only starts with the auth origin must remain forbidden.
    await page.evaluate(() => {
      const form = document.querySelector('form[action="/tesla/owner/connect"]');
      form.action = 'https://auth.tesla.localhost.not-tesla.invalid/collect';
      form.requestSubmit();
    });
    await expect.poll(() => violations.length).toBeGreaterThan(0);
    expect(external).toBe(0);
    console.log(JSON.stringify({synthetic_oauth_pages: syntheticOAuthPages,
      external_requests: external, unrelated_form_blocked: true}));
  } catch (error) {
    console.error(JSON.stringify({csp_violations: violations, synthetic_oauth_pages: syntheticOAuthPages, network, page: page.url().split('?')[0]}));
    throw error;
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
