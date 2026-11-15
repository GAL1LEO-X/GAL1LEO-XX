const {test, expect} = require('@playwright/test');
test.use({baseURL:'https://127.0.0.1:8876', ignoreHTTPSErrors:true});

test.beforeEach(async ({request}) => {
  await request.post('/test/configure/activated');
});
test.afterEach(async ({request}) => {
  await request.post('/test/configure/activated');
});

test('prepared instance blocks pairing until separately activated, then guides phone and ChatGPT', async ({page,request}) => {
  await request.post('/test/configure/prepared');
  await page.goto('/test/login');
  await expect(page.locator('#activation-state')).toContainText("Activation required");
  await expect(page.locator('#phone-link')).toBeHidden();
  await expect(page.locator('#chatgpt-state')).toContainText('does not grant ChatGPT permissions');
  expect((await (await request.get('/test/receipt')).json()).requests).toEqual([]);
  await page.goto('/connect');
  await expect(page.locator('#activation-required')).toBeVisible();
  await expect(page.locator('#pairing')).toBeHidden();
  const rejected = await page.evaluate(async () => {
    const response = await fetch('/connect/api/pair',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.body.dataset.csrf},body:JSON.stringify({mode:'qr'})});
    return {status:response.status,body:await response.json()};
  });
  expect(rejected.status).toBe(409);
  expect((await (await request.get('/test/receipt')).json()).requests).toEqual([]);
  // Test-only config transition, not a claim that GUI can activate a host.
  await request.post('/test/configure/activated');
  await page.getByRole('link',{name:"Back to instance administration"}).click();
  await expect(page.locator('#phone-link')).toHaveText("Connect this phone");
  await page.locator('#phone-link').click();
  await expect(page.locator('#status-title')).toContainText('Ready to connect');
  await page.getByLabel("WhatsApp number with country code").fill('+10000000000');
  await page.getByRole('button',{name:"Generate temporary code",exact:true}).click();
  await expect(page.locator('#pairing-code')).toHaveText('TEST-ONLY');
  await request.post('/test/phone/WORKING');
  await expect(page.locator('#connected')).toBeVisible();
  await expect(page.locator('#pairing-code')).toHaveText('');
  await page.getByRole('link',{name:"Back to instance administration"}).click();
  await expect(page.locator('#phone-state')).toContainText('Phone connected');
  await expect(page.locator('#chatgpt-state')).toContainText('cannot verify that consent');
  const receipt = await (await request.get('/test/receipt')).json();
  expect(JSON.stringify(receipt.journal)).not.toContain('TEST-ONLY');
  expect(JSON.stringify(receipt.journal)).not.toContain('10000000000');
});

test('FAILED reconnect uses existing restart and WORKING cannot be recreated', async ({page,request}) => {
  await request.post('/test/phone/FAILED');
  await page.goto('/test/login');
  await expect(page.locator('#phone-link')).toHaveText("Reconnect this phone");
  await page.locator('#phone-link').click();
  let releaseQr, observeQr;
  const qrGate = new Promise(resolve => { releaseQr = resolve; });
  const qrRequested = new Promise(resolve => { observeQr = resolve; });
  await page.route(url => url.pathname === '/connect/qr', async route => {
    if (route.request().method() !== 'GET') return route.continue();
    observeQr();
    await qrGate;
    await route.continue();
  });
  try {
    await page.getByRole('button',{name:"Use the QR code",exact:true}).click();
    await expect(page.locator('#qr-image')).toBeVisible();
    await qrRequested;
    // Visibility precedes the image request completing; it is not a QR receipt.
    expect((await (await request.get('/test/receipt')).json()).qr_reads).toBe(0);
    const qrResponse = page.waitForResponse(response =>
      new URL(response.url()).pathname === '/connect/qr' && response.request().method() === 'GET');
    releaseQr();
    expect((await qrResponse).status()).toBe(200);
  } finally {
    releaseQr();
  }
  let receipt = await (await request.get('/test/receipt')).json();
  expect(receipt.requests.filter(row => row.path.endsWith('/restart')).length).toBe(1);
  expect(receipt.requests.filter(row => row.path.endsWith('/start')).length).toBe(0);
  expect(receipt.qr_reads).toBeGreaterThan(0);
  await request.post('/test/phone/WORKING');
  await expect(page.locator('#connected')).toBeVisible();
  const before = receipt.requests.filter(row => row.method === 'POST').length;
  const result = await page.evaluate(async () => (await fetch('/connect/api/pair',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':document.body.dataset.csrf},body:JSON.stringify({mode:'qr'})})).json());
  expect(result.connected).toBe(true);
  receipt = await (await request.get('/test/receipt')).json();
  expect(receipt.requests.filter(row => row.method === 'POST').length).toBe(before);
  expect(JSON.stringify(receipt.journal)).not.toContain('qr_url');
});

test('expired owner session clears pairing credentials and blocks direct APIs', async ({page,request}) => {
  await request.post('/test/phone/SCAN_QR_CODE');
  await page.goto('/test/login');
  await page.locator('#phone-link').click();
  await page.getByRole('button',{name:"Use the QR code",exact:true}).click();
  await expect(page.locator('#qr-image')).toBeVisible();
  await request.post('/test/expire');
  await expect(page.locator('#session-expired')).toBeVisible();
  await expect(page.locator('#qr-image')).not.toHaveAttribute('src');
  await expect(page.locator('#pairing-code')).toHaveText('');
  expect(await page.evaluate(async () => (await fetch('/connect/qr')).status)).toBe(401);
  expect(await page.evaluate(async () => (await fetch('/admin/api/connection')).status)).toBe(401);
  await page.goto('/admin');
  await expect(page.getByRole('heading',{name:"Sign-in required"})).toBeVisible();
  await page.goto('/test/login');
  await expect(page.locator('#phone-state')).toContainText('Ready for a temporary code');
  await request.post('/test/expire');
  await page.getByRole('button',{name:"Refresh observation"}).click();
  await expect(page.getByRole('heading',{name:"Sign-in required"})).toBeVisible();
});
