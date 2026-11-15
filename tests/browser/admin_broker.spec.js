const {test, expect} = require('@playwright/test');
test.use({baseURL:'https://127.0.0.1:8876', ignoreHTTPSErrors:true});
test.afterEach(async ({request}) => {await request.post('/test/broker/stop');});

test('shared host action declares every affected instance and survives a lost HTTP response', async ({page, request}) => {
  const setup = await (await request.post('/test/broker/start', {data:{hold:false}})).json();
  await page.goto('/test/login');
  const action = page.locator('#host-actions li').filter({hasText:setup.approval});
  await expect(action).toContainText("Affected instances: alpha, beta");
  await expect(action.locator('.operation-description')).toHaveText('Synthetic shared update');
  await action.getByRole('button', {name:"Confirm operation"}).click();
  await expect(page.locator('#confirmation-details')).toContainText('Intervento condiviso');
  await expect(page.locator('#confirmation-details')).toContainText('alpha, beta');
  await expect(page.locator('#confirmation-details')).toContainText('Synthetic shared update');
  await page.locator('#confirmation-input').fill('release.activate:alpha');
  await page.locator('#confirm-button').click();
  await expect(page.locator('#error')).toContainText("Confirm esplicitamente");
  expect((await (await request.get('/test/broker/state')).json()).effects).toBe(0);
  let calls = 0;
  await page.route('**/admin/api/operations', async route => {
    calls++;
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    await route.abort('failed');
  });
  await action.getByRole('button', {name:"Confirm operation"}).click();
  await page.locator('#confirmation-input').fill('release.activate:installation');
  await page.locator('#confirm-button').click();
  await expect(action).toContainText("Approvazione unavailable");
  const observed = await (await request.get('/test/broker/state')).json();
  expect(observed.effects).toBe(1);
  expect(observed.ids).toHaveLength(1);
  await expect(page.locator('#operations article').filter({hasText:observed.ids[0]})).toContainText("Completed");
  await page.reload();
  await expect(page.locator('#operations article').filter({hasText:observed.ids[0]})).toContainText("Completed");
  await page.locator('#receipt-id').fill(observed.ids[0]);
  await page.getByRole('button', {name:"Read receipt by identifier"}).click();
  await expect(page.locator('#notice')).toContainText("Receipt " + observed.ids[0] + ": Completed");
  expect(calls).toBe(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('an uncertain host request can only read its durable receipt without resubmitting', async ({page, request}) => {
  let submissions = 0;
  page.on('request', sent => {
    if (sent.method() === 'POST' && new URL(sent.url()).pathname === '/admin/api/operations') submissions++;
  });
  const setup = await (await request.post('/test/broker/start', {data:{hold:true}})).json();
  await page.goto('/test/login');
  const action = page.locator('#host-actions li').filter({hasText:setup.approval});
  await action.getByRole('button', {name:"Confirm operation"}).click();
  await page.locator('#confirmation-input').fill('release.activate:installation');
  await page.locator('#confirm-button').click();
  await expect(action).toContainText("Approvazione unavailable");
  const observed = await (await request.get('/test/broker/state')).json();
  const row = page.locator('#operations article').filter({hasText:observed.ids[0]});
  await expect(row).toContainText('Esito incerto');
  await expect(row.getByRole('button', {name:"Check server receipt"})).toBeVisible();
  await row.getByRole('button', {name:"Check server receipt"}).click();
  await expect(page.locator('#notice')).toContainText("Receipt " + observed.ids[0] + ': Esito incerto');
  await expect(row).toContainText('Esito incerto');
  expect(submissions).toBe(1);
  await request.post('/test/broker/release');
  // Releasing the synthetic executor does not mean its durable commit finished.
  await expect.poll(async () => {
    const state = await (await request.get('/test/broker/state')).json();
    return state.states[observed.ids[0]];
  }).toBe('completed');
  await row.getByRole('button', {name:"Check server receipt"}).click();
  await expect(row).toContainText("Completed");
  expect((await (await request.get('/test/broker/state')).json()).effects).toBe(1);
  expect(submissions).toBe(1);
});

test('restore proposals for one instance retain distinct descriptions as plain text through confirmation', async ({page, request}) => {
  const setup = await (await request.post('/test/broker/start', {data:{hold:false}})).json();
  await page.goto('/test/login');
  const [first, second] = setup.restore_approvals;
  const firstAction = page.locator('#host-actions li').filter({hasText:first.approval});
  const secondAction = page.locator('#host-actions li').filter({hasText:second.approval});
  await expect(firstAction.locator('.operation-description')).toHaveText(first.description);
  await expect(secondAction.locator('.operation-description')).toHaveText(second.description);
  await expect(page.locator('#host-actions img')).toHaveCount(0);
  await firstAction.getByRole('button', {name:"Confirm operation"}).click();
  await expect(page.locator('#confirmation-label')).toHaveText('backup.restore:alpha');
  await expect(page.locator('#confirmation-details')).toContainText(first.description);
  await expect(page.locator('#confirmation-details')).toContainText("Affected instances: alpha");
  await page.locator('#confirmation').getByRole('button', {name:"Cancel", exact:true}).click();
  await secondAction.getByRole('button', {name:"Confirm operation"}).click();
  await expect(page.locator('#confirmation-label')).toHaveText('backup.restore:alpha');
  await expect(page.locator('#confirmation-details')).toContainText(second.description);
  await expect(page.locator('#confirmation-details')).not.toContainText(first.description);
  await expect(page.locator('#confirmation-details img')).toHaveCount(0);
  expect(await page.evaluate(() => window.adminDescriptionExecuted)).toBeUndefined();
  await page.locator('#confirmation-input').fill('backup.restore:alpha');
  await page.locator('#confirm-button').click();
  await expect(secondAction).toContainText("Approvazione unavailable");
  const observed = await (await request.get('/test/broker/state')).json();
  expect(observed.executed_approvals).toEqual([second.approval]);
  await expect(firstAction.getByRole('button', {name:"Confirm operation"})).toBeVisible();
  expect(await page.evaluate(() => window.adminDescriptionExecuted)).toBeUndefined();
});
