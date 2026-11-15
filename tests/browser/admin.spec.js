const {test, expect} = require('@playwright/test');
test.use({baseURL:'https://127.0.0.1:8876', ignoreHTTPSErrors:true});

test('diagnostic cards separate acknowledged history from active uncertain actions', async ({page}) => {
  let active = 0;
  await page.route('**/admin/api/status', async route => {
    const response = await route.fetch();
    const value = await response.json();
    value.connection.uncertain_sends = 7 + active;
    value.connection.uncertain_active = active;
    value.connection.uncertain_known_history = 7;
    await route.fulfill({response, json:value});
  });
  await page.goto('/test/login');
  const current = page.locator('#status-cards article').filter({hasText:"Uncertain outcomes requiring review"});
  const history = page.locator('#status-cards article').filter({hasText:"Acknowledged historical uncertain outcomes"});
  await expect(current.locator('p')).toHaveText('0');
  await expect(history.locator('p')).toHaveText('7');
  active = 1;
  await page.getByRole('button', {name:"Refresh observation"}).click();
  await expect(current.locator('p')).toHaveText('1');
  await expect(history.locator('p')).toHaveText('7');
});

test('actual admin API requires a session and enforces CSRF and target confirmation', async ({page, request}) => {
  const denied = await request.get('/admin/api/status');
  expect(denied.status()).toBe(401);
  await page.goto('/admin');
  await expect(page.getByRole('heading', {name:"Sign-in required"})).toBeVisible();
  await page.goto('/test/login');
  await expect(page.locator('#summary')).toContainText('schema 8');
  const job = await (await request.post('/test/history')).json();
  await page.getByRole('button', {name:"Refresh observation"}).click();
  const payload = {id:'a'.repeat(32), operation:'history.cancel', target:job.id, arguments:{}, confirmation:'history.cancel:'+job.id};
  expect(await page.evaluate(async body => (await fetch('/admin/api/operations', {
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)
  })).status, payload)).toBe(403);
  expect((await (await request.get('/test/history/'+job.id)).json()).state).toBe('running');
  const card = page.locator('#history article').filter({hasText:job.id});
  await card.getByRole('button', {name:"Cancel import"}).click();
  await page.locator('#confirmation-input').fill('history.cancel:other');
  await page.locator('#confirm-button').click();
  await expect(page.locator('#error')).toContainText("Explicitly confirm");
  expect((await (await request.get('/test/history/'+job.id)).json()).state).toBe('running');
  await card.getByRole('button', {name:"Cancel import"}).click();
  await page.locator('#confirmation-input').fill('history.cancel:'+job.id);
  await page.locator('#confirm-button').click();
  await expect(page.locator('#operations article').filter({hasText:job.id})).toContainText("Completed");
  expect((await (await request.get('/test/history/'+job.id)).json()).state).toBe('cancelled');
  await page.getByRole('button', {name:"Read latest logs"}).click();
  await expect(page.locator('#logs')).toContainText('admin.finished');
  await expect(page.locator('#logs')).not.toContainText(job.id);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({path: 'work/test-results/admin-' + test.info().project.name + '.png', fullPage:true});
  await page.getByRole('button', {name:"Sign out", exact:true}).click();
  await expect(page.getByRole('heading', {name:"Sign-in required"})).toBeVisible();
});

test('instance preview uses real profile validation and does not claim activation', async ({page}) => {
  await page.goto('/test/login');
  const profile = {format:'whatsapp-installation-v1', paths:{project:'/srv/demo-code',configuration:'/etc/demo-config',state:'/var/lib/demo-state',gateway:'/var/lib/demo-gateway',backup:'/var/backups/demo-copy',administration_code:'/usr/local/lib/demo-admin',administration_state:'/var/lib/demo-admin'}, services:{prefix:'demo',recovery:'demo-recover'}, accounts:{alpha:'demo-alpha'}, ports:{alpha:{bridge:18820,gateway:18821}}, authentication:'external-oidc',frontend:'new'};
  await page.locator('#profile').fill(JSON.stringify(profile));
  await page.locator('#slug').fill('beta'); await page.locator('#account').fill('demo-beta');
  await page.locator('#bridge').fill('18830'); await page.locator('#gateway').fill('18831');
  await page.getByRole('button', {name:"Check preview"}).click();
  await page.locator('#confirmation-input').fill('instance.preview:beta');
  await page.locator('#confirm-button').click();
  await expect(page.locator('#preview-result')).toContainText('preview_only');
  await expect(page.locator('#preview-result')).toContainText('"resources_reserved": false');
  await expect(page.locator('#host-actions')).toContainText("Restore backup");
  await expect(page.locator('#host-actions')).toContainText('Administration channel not configured');
});

test('a delayed real response does not discard the next confirmation', async ({page, request}) => {
  const first = await (await request.post('/test/history')).json();
  const second = await (await request.post('/test/history')).json();
  await page.goto('/test/login');
  await expect(page.locator('#history')).toContainText(first.id);
  let release;
  const held = new Promise(resolve => {release = resolve;});
  let observed;
  const received = new Promise(resolve => {observed = resolve;});
  await page.route('**/admin/api/operations', async route => {
    const result = await route.fetch();
    if (route.request().postDataJSON().target === first.id) {observed(); await held;}
    await route.fulfill({response:result});
  });
  await page.locator('#history article').filter({hasText:first.id}).getByRole('button', {name:"Pause"}).click();
  await page.locator('#confirmation-input').fill('history.pause:'+first.id);
  await page.locator('#confirm-button').click();
  await received;
  await page.locator('#history article').filter({hasText:second.id}).getByRole('button', {name:"Cancel import"}).click();
  release();
  await expect(page.locator('#operations article').filter({hasText:first.id})).toContainText("Completed");
  await page.locator('#confirmation-input').fill('history.cancel:'+second.id);
  await page.locator('#confirm-button').click();
  await expect(page.locator('#operations article').filter({hasText:second.id})).toContainText("Completed");
  expect((await (await request.get('/test/history/'+second.id)).json()).state).toBe('cancelled');
});

test('a recovered status read clears its historical error', async ({page}) => {
  await page.goto('/test/login');
  await expect(page.locator('#notice')).toContainText("Observation refreshed");
  let fail = true;
  await page.route('**/admin/api/status', async route => {
    if (fail) {fail = false; await route.abort('failed');}
    else await route.continue();
  });
  await page.getByRole('button',{name:"Refresh observation"}).click();
  await expect(page.locator('#error')).toBeVisible();
  await expect(page.locator('#notice')).toContainText('not refreshed');
  await page.getByRole('button',{name:"Refresh observation"}).click();
  await expect(page.locator('#notice')).toContainText("Observation refreshed");
  await expect(page.locator('#error')).toBeHidden();
});

for (const failure of ['lost', 'server-error']) test(failure + ' logout response verifies actual revocation without repeating POST', async ({page}) => {
  await page.goto('/test/login');
  await expect(page.locator('#notice')).toContainText("Observation refreshed");
  let posts = 0;
  await page.route('**/connect/api/logout', async route => {
    posts++;
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    if (failure === 'lost') await route.abort('failed');
    else await route.fulfill({status:502,json:{error:'synthetic response failure after actual logout'}});
  });
  await page.getByRole('button',{name:"Sign out",exact:true}).click();
  await expect(page.getByRole('heading',{name:"Sign-in required"})).toBeVisible();
  expect(posts).toBe(1);
  expect(await page.evaluate(async () => (await fetch('/admin/api/status')).status)).toBe(401);
});
