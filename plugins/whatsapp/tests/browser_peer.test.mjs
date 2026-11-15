import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserPeer } from '../qa/browser_peer.mjs';

const step = {
  executor: 'browser', effect: 'write', status: 'execute_once', action: 'send_text',
  arguments: { marker: 'QA qa-synthetic', text: 'QA qa-synthetic reply', chat_label: 'Synthetic' },
};

function peer({ existing = false, draft = '', typedOverride } = {}) {
  const mutations = [];
  const instance = new BrowserPeer({ playwright: { domSnapshot: async () => '' } });
  instance.identity = { name: 'Synthetic', phone: '199999998' };
  instance.verifyIdentity = async () => ({ identity_matches: true });
  const composer = {
    innerText: async () => draft,
    pressSequentially: async text => { mutations.push(['type', text]); draft = typedOverride ?? text; },
    click: async () => mutations.push(['focus']),
  };
  instance.openChat = async () => ({ getByRole: role => role === 'textbox' ? composer : {
    click: async () => { mutations.push(['send']); existing = true; },
  } });
  instance.one = async locator => locator;
  instance.observeText = async () => ({ match_count: existing ? 1 : 0 });
  return { instance, mutations };
}

test('an already visible campaign message is not sent again', async () => {
  const { instance, mutations } = peer({ existing: true });
  assert.equal((await instance.execute(step)).already_present, true);
  assert.deepEqual(mutations, []);
});

test('an unrelated draft is preserved', async () => {
  const { instance, mutations } = peer({ draft: 'User draft' });
  await assert.rejects(instance.execute(step), /Existing draft preserved/);
  assert.deepEqual(mutations, []);
});

test('a recovery observation cannot accidentally become a new send', async () => {
  const { instance, mutations } = peer();
  await assert.rejects(instance.execute({ ...step, status: 'observe' }), /fresh journal-issued/);
  assert.deepEqual(mutations, []);
});

test('failed identity refresh prevents typing', async () => {
  const { instance, mutations } = peer();
  instance.verifyIdentity = async () => { throw new Error('Identity changed'); };
  await assert.rejects(instance.execute(step), /Identity changed/);
  assert.deepEqual(mutations, []);
});

test('a misdirected or incomplete draft cannot reach the send action', async () => {
  const { instance, mutations } = peer({ typedOverride: 'incomplete' });
  await assert.rejects(instance.execute(step), /Draft does not match/);
  assert.equal(mutations.some(([action]) => action === 'send'), false);
});

test('only the exact authorized text is sent once after focusing the composer', async () => {
  const { instance, mutations } = peer();
  assert.equal((await instance.execute(step)).match_count, 1);
  assert.deepEqual(mutations, [['focus'], ['type', step.arguments.text], ['send']]);
});
