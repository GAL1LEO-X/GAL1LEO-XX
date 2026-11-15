const {test, expect} = require('@playwright/test');
test.use({baseURL:'https://127.0.0.1:8876', ignoreHTTPSErrors:true});
function deferred() {let resolve; const promise = new Promise(done=>{resolve=done;}); return {promise,resolve};}
const card = (page,id) => page.locator('#history article').filter({hasText:id});
async function login(page) {await page.goto('/test/login'); await expect(page.locator('#notice')).toContainText("Observation aggiornata");}
test.beforeEach(async ({page,request}) => {
  await request.post('/test/configure/activated');
  await page.route('**/*', route => new URL(route.request().url()).hostname === '127.0.0.1' ? route.continue() : route.abort());
});
test.afterEach(async ({request}) => {await request.post('/test/admin-records/reset');});

test('older reads cannot replace a completed operation or its receipt', async ({page,request}) => {
  const id = (await (await request.post('/test/history')).json()).id;
  await login(page);
  const gate=deferred(), captured=deferred(), finished=deferred(); let hold=true;
  await page.route('**/admin/api/status*', async route=>{
    const response=await route.fetch();
    if (hold) {hold=false; captured.resolve(); await gate.promise; await route.fulfill({response}); finished.resolve();}
    else await route.fulfill({response});
  });
  try {
    await page.locator('#refresh').click(); await captured.promise;
    await card(page,id).getByRole('button',{name:"Pause"}).click();
    await page.locator('#confirmation-input').fill('history.pause:'+id);
    await page.locator('#confirm-button').click();
    await expect(card(page,id)).toContainText("Paused");
    gate.resolve(); await finished.promise;
    // A subsequent connection read/event-loop turn must not commit the old status.
    await page.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    await expect(card(page,id)).toContainText("Paused");
    await expect(page.locator('#operations article').filter({hasText:id})).toContainText("Completed");
    expect((await (await request.get('/test/history/'+id)).json()).state).toBe('paused');
  } finally {gate.resolve();}
});

test('incomplete observations retain the previous coherent view and recover', async ({page}) => {
  await login(page);
  const original=await page.locator('#instance').innerText();
  await page.route('**/admin/api/status*',async route=>{
    const response=await route.fetch(); const value=await response.json(); value.instance='NEW OBSERVATION';
    await route.fulfill({response,json:value});
  });
  await page.route('**/admin/api/connection',route=>route.abort('failed'),{times:1});
  await page.locator('#refresh').click();
  await expect(page.locator('#notice')).toContainText('non aggiornata');
  await expect(page.locator('#instance')).toHaveText(original);
  await page.locator('#refresh').click();
  await expect(page.locator('#instance')).toHaveText('NEW OBSERVATION');
  await expect(page.locator('#error')).toBeHidden();
});

test('a directly observed receipt survives a failed follow-up snapshot without repeating the action', async ({page,request}) => {
  const id=(await (await request.post('/test/history')).json()).id;
  await login(page);
  let posts=0;
  page.on('request',request=>{if(request.method()==='POST' && request.url().endsWith('/admin/api/operations'))posts++;});
  await page.route('**/admin/api/status*',route=>route.abort('failed'),{times:1});
  await card(page,id).getByRole('button',{name:"Pause"}).click();
  await page.locator('#confirmation-input').fill('history.pause:'+id);
  await page.locator('#confirm-button').click();
  await expect(page.locator('#notice')).toContainText('non aggiornata');
  await expect(page.locator('#operations article').filter({hasText:id})).toContainText("Completed");
  expect((await (await request.get('/test/history/'+id)).json()).state).toBe('paused');
  await page.locator('#refresh').click();
  await expect(card(page,id)).toContainText("Paused");
  expect(posts).toBe(1);
});

test('both bounded lists reach and control records beyond the first hundred', async ({page,request}) => {
  const ids=await (await request.post('/test/admin-records')).json();
  await login(page);
  await expect(page.locator('#history article')).toHaveCount(100);
  await expect(page.locator('#subscriptions article')).toHaveCount(100);
  await expect(page.locator('#history-page')).toContainText('Altri elementi');
  await expect(page.locator('#subscriptions-page')).toContainText('Altri elementi');
  await page.locator('#history-next').click();
  await expect(card(page,ids.history)).toContainText("In progress");
  await expect(page.locator('#history article')).toHaveCount(1);
  await expect(page.locator('#history-next')).toBeDisabled();
  await page.locator('#subscriptions-next').click();
  const sub=page.locator('#subscriptions article').filter({hasText:ids.subscription});
  await expect(sub).toContainText("Active");
  await sub.getByRole('button',{name:"Disable subscription"}).click();
  await page.locator('#confirmation-input').fill('subscription.disable:'+ids.subscription);
  await page.locator('#confirm-button').click();
  await expect(sub).toContainText("Inactive");
  await card(page,ids.history).getByRole('button',{name:"Pause"}).click();
  await page.locator('#confirmation-input').fill('history.pause:'+ids.history);
  await page.keyboard.press('Escape');
  await expect(page.locator('#confirmation')).not.toBeVisible();
  expect((await (await request.get('/test/history/'+ids.history)).json()).state).toBe('running');
  await card(page,ids.history).getByRole('button',{name:"Pause"}).click();
  await page.locator('#confirmation-input').fill('history.pause:'+ids.history);
  await page.locator('#confirm-button').click();
  await expect(card(page,ids.history)).toContainText("Paused");
  await page.locator('#history-previous').click();
  await expect(page.locator('#history article')).toHaveCount(100);
  await page.locator('#history-next').click();
  await expect(card(page,ids.history)).toContainText("Paused");
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(page.viewportSize().width);
});

test('pagination errors and repeated clicks preserve position, then expiry requires login', async ({page,request}) => {
  const ids=await (await request.post('/test/admin-records')).json();
  await login(page);
  await page.route('**/admin/api/status*',route=>route.abort('failed'),{times:1});
  await page.locator('#history-next').click();
  await expect(page.locator('#notice')).toContainText('non aggiornata');
  await expect(page.locator('#history article')).toHaveCount(100);
  await expect(page.locator('#history-previous')).toBeDisabled();
  const gate=deferred(),started=deferred(); let calls=0;
  await page.route('**/admin/api/status*',async route=>{calls++;started.resolve();await gate.promise;await route.continue();});
  try {
    await page.locator('#history-next').evaluate(button=>{button.click();button.click();});
    await started.promise;
    await expect(page.locator('#history-next')).toBeDisabled();
    gate.resolve();
    await expect(card(page,ids.history)).toBeVisible();
    expect(calls).toBe(1);
  } finally {gate.resolve();}
  await request.post('/test/expire');
  await page.locator('#history-previous').click();
  await expect(page.getByRole('heading',{name:"Sign-in required"})).toBeVisible();
});

test('narrow keyboard navigation keeps list feedback and footer controls reachable', async ({page,request}) => {
  await request.post('/test/admin-records');
  await page.setViewportSize({width:320,height:640});
  await login(page);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth)).toBeLessThanOrEqual(page.viewportSize().width);
  await expect(page.getByRole('group',{name:"Pages · History imports"})).toBeVisible();
  await page.locator('#history-next').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#history-page')).toBeFocused();
  await expect(page.locator('#history-page')).toContainText("Page 2");
  await page.locator('#history-previous').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#history-page')).toBeFocused();
  await expect(page.locator('#history-page')).toContainText("Page 1");
  await page.locator('#logs-button').click({timeout:5000});
  await expect(page.locator('#logs')).toContainText('last_100_in_bounded_tail_only');
  await page.locator('#logout').click({timeout:5000});
  await expect(page.getByRole('heading',{name:"Sign-in required"})).toBeVisible();
});

test('Escape after a prior confirmation dispatches no POST after the close-event barrier', async ({page,request}) => {
  const first=(await (await request.post('/test/history')).json()).id;
  const second=(await (await request.post('/test/history')).json()).id;
  await login(page);
  let networkPosts=0;
  page.on('request', request=>{if(request.method()==='POST' && request.url().endsWith('/admin/api/operations'))networkPosts++;});
  await page.evaluate(()=>{
    const nativeFetch=window.fetch.bind(window);
    window.qa174OperationPosts=[];
    window.fetch=(input, options)=>{
      if (String(input)==='/admin/api/operations' && options?.method==='POST') window.qa174OperationPosts.push(JSON.parse(options.body));
      return nativeFetch(input, options); // Observe synchronously; never suppress the real request.
    };
  });
  await card(page,first).getByRole('button',{name:"Pause"}).click();
  await page.locator('#confirmation-input').fill('history.pause:'+first);
  await page.locator('#confirm-button').click();
  await expect(card(page,first)).toContainText("Paused");
  await card(page,second).getByRole('button',{name:"Cancel import"}).click();
  await page.locator('#confirmation-input').fill('history.cancel:'+second);
  expect(await page.locator('#confirmation').evaluate(dialog=>dialog.returnValue)).toBe('confirm');
  await page.evaluate(()=>{
    const dialog=document.getElementById('confirmation');
    window.qa174Closed=new Promise(resolve=>{
      const events=[];
      dialog.addEventListener('cancel',()=>events.push({type:'cancel',value:dialog.returnValue}),{once:true});
      // Product's earlier close listener starts fetch synchronously before its
      // first await. This later listener is a causal barrier, not a timed sleep.
      dialog.addEventListener('close',()=>resolve({events:[...events,{type:'close',value:dialog.returnValue}],
        posts:window.qa174OperationPosts.slice()}),{once:true});
    });
  });
  await page.keyboard.press('Escape');
  const closed=await page.evaluate(()=>window.qa174Closed);
  expect(closed.events).toEqual([{type:'cancel',value:'confirm'},{type:'close',value:''}]);
  expect(closed.posts).toHaveLength(1);
  expect(closed.posts[0].target).toBe(first);
  expect((await (await request.get('/test/history/'+second)).json()).state).toBe('running');
  expect(networkPosts).toBe(1);
  // Positive control proves the observer and mutation route remain functional.
  await card(page,second).getByRole('button',{name:'Cancel import'}).click();
  await page.locator('#confirmation-input').fill('history.cancel:'+second);
  await page.locator('#confirm-button').click();
  await expect(card(page,second)).toContainText('Annullata');
  expect(networkPosts).toBe(2);
  expect(await page.evaluate(()=>window.qa174OperationPosts.length)).toBe(2);
});
