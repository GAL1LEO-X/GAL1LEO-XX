/**
 * Browser peer for the supported Codex cua_repl Tab API.
 * Import this module in cua_repl and inject the already selected Chrome tab.
 * No HTTP client, credentials, hidden WhatsApp state or private API is used.
 * All message actions require a journal-issued live step and current UI proof.
 */
export class BrowserPeer {
  constructor(tab) {
    this.tab = tab;
    this.identity = null;
  }

  async one(locator, description) {
    const visible = locator.filter({ visible: true });
    await visible.waitFor({ state: 'visible', timeoutMs: 5000 });
    if (await visible.count() !== 1) throw new Error(`Ambiguous or missing UI control: ${description}`);
    return visible;
  }

  async inspect() {
    const snapshot = await this.tab.playwright.domSnapshot();
    return {
      authenticated_ui: snapshot.includes('Nuova chat') && snapshot.includes('Chat'),
      calls_advertised: snapshot.includes("chiamate e videochiamate sono hour available"),
      // The raw snapshot remains in the browser context, not a public report.
      url: await this.tab.url(),
    };
  }

  async verifyIdentity({ expected_name, expected_phone }) {
    this.identity = null;
    const me = await this.one(this.tab.playwright.getByRole('button', { name: 'Tu', exact: true }), 'Tu');
    await me.click();
    await this.tab.playwright.domSnapshot();
    const profile = await this.one(this.tab.playwright.getByRole('button', { name: 'Visualizza profilo', exact: true }), 'Visualizza profilo');
    await profile.click();
    await this.tab.playwright.domSnapshot();
    await this.one(this.tab.playwright.getByRole('heading', { name: 'Modifica profilo', exact: true }), 'profile heading');
    await this.one(this.tab.playwright.getByText('Telefono', { exact: true }), 'profile phone field');
    const proof = await this.tab.playwright.evaluate(({ name, phone }) => {
      const text = document.body.innerText;
      const numbers = text.match(/\+\d[\d\s()-]{6,25}\d/g) || [];
      return {
        name_matches: text.split('\n').some(line => line.trim() === name),
        phone_matches: numbers.some(value => value.replace(/\D/g, '') === phone.replace(/\D/g, '')),
      };
    }, { name: expected_name, phone: expected_phone });
    const chat = await this.one(this.tab.playwright.getByRole('button', { name: 'Chat', exact: true }), 'Chat');
    await chat.click();
    await this.tab.playwright.domSnapshot();
    const identity_matches = proof.name_matches && proof.phone_matches;
    this.identity = identity_matches ? { name: expected_name, phone: expected_phone } : null;
    if (!identity_matches) throw new Error('The connected browser account does not match the approved TESTX identity');
    return { identity_matches, ...proof };
  }

  authorize(step) {
    if (!this.identity) throw new Error('Verify the browser identity first');
    if (step.executor !== 'browser' || step.effect !== 'write' || step.status !== 'execute_once') {
      throw new Error('A fresh journal-issued live browser instruction is required');
    }
    if (!step.arguments?.marker?.startsWith('QA qa-')) throw new Error('Missing unique campaign marker');
    if (!step.arguments.chat_label) throw new Error('Missing verified conversation label');
  }

  async openChat(label) {
    const active = this.tab.playwright.locator('#main');
    const heading = active.getByRole('button').filter({
      has: this.tab.playwright.getByText(label, { exact: true }),
    }).filter({ visible: true });
    if (await heading.count() === 1) return active;
    const search = await this.one(this.tab.playwright.getByRole('textbox', { name: 'Cerca o avvia una nuova chat', exact: true })
      .or(this.tab.playwright.getByRole('textbox', { name: '', exact: true })), 'chat search');
    await search.click();
    await search.press('ControlOrMeta+A');
    await search.press('Backspace');
    await search.pressSequentially(label);
    const query = await search.evaluateAll(elements => elements.map(e => e.tagName === 'INPUT' ? e.value : e.innerText));
    if (query.length !== 1 || query[0].trim() !== label) throw new Error('Search text was not entered in the intended field');
    await this.tab.playwright.domSnapshot();
    const target = await this.one(this.tab.playwright.getByRole('grid', { name: 'Risultati della ricerca.', exact: true })
      .getByTestId('cell-frame-container').filter({ has: this.tab.playwright.getByText(label, { exact: true }) }),
      'exact approved conversation');
    await target.click();
    await this.tab.playwright.domSnapshot();
    // Discover the actual visible DOM before selecting the conversation root.
    const root = await this.tab.playwright.evaluate(() => {
      const candidates = Array.from(document.querySelectorAll('main, [role="main"], [id]'))
        .filter(element => element.id === 'main' || element.getAttribute('role') === 'main' || element.tagName === 'MAIN')
        .filter(element => element.getBoundingClientRect().width > 0 && element.getBoundingClientRect().height > 0);
      const selected = candidates.find(element => element.id === 'main');
      return selected ? { selector: '#main', text: selected.innerText } : null;
    });
    if (!root) throw new Error('Cannot locate the active conversation');
    const conversation = this.tab.playwright.locator(root.selector);
    await this.one(conversation.getByRole('button').filter({
      has: this.tab.playwright.getByText(label, { exact: true }),
    }), 'approved conversation heading');
    return conversation;
  }

  async observeText(root, expected) {
    // Visible text must belong to a message container, not a sidebar preview,
    // draft composer or quoted occurrence. Collapse duplicate descendant hits.
    const matches = await root.getByTestId('selectable-text').evaluateAll((elements, text) => {
      const messages = new Map();
      const rendered = node => {
        if (node.nodeType === Node.TEXT_NODE) return node.nodeValue;
        if (node.nodeType !== Node.ELEMENT_NODE) return '';
        if (node.tagName === 'IMG') return node.getAttribute('data-plain-text') || node.getAttribute('alt') || '';
        if (node.tagName === 'BR') return '\n';
        return Array.from(node.childNodes).map(rendered).join('');
      };
      for (const element of elements) {
        if (element.parentElement?.closest('[data-testid="selectable-text"]')) continue;
        if (element.closest('footer, [contenteditable="true"]')) continue;
        const message = element.closest('[data-id]');
        if (!message || message.getBoundingClientRect().height === 0) continue;
        if (element.closest('[data-testid="quoted-message"]')) continue;
        const actual = rendered(element).replace(/\r\n/g, '\n');
        if (actual !== text) continue;
        messages.set(message.getAttribute('data-id'), { text: actual, dom_message_id: message.getAttribute('data-id') });
      }
      return [...messages.values()];
    }, expected);
    return { match_count: matches.length, text: matches.length === 1 ? expected : null,
      dom_message_id: matches.length === 1 ? matches[0].dom_message_id : null };
  }

  async execute(step) {
    if (step.action === 'verify_identity') return this.verifyIdentity(step.arguments);
    if (step.action === 'inspect') return this.inspect();
    this.authorize(step);
    // An account can be switched between steps in a user-owned browser tab.
    const expected = this.identity;
    await this.verifyIdentity({ expected_name: expected.name, expected_phone: expected.phone });
    const root = await this.openChat(step.arguments.chat_label);
    if (step.action === 'observe_message') {
      let observation = await this.observeText(root, step.arguments.expected_text);
      for (let page = 0; observation.match_count === 0 && page < 3; page++) {
        const messages = root.getByRole('row').filter({ has: this.tab.playwright.getByTestId('msg-container') });
        if (!await messages.count()) break;
        await messages.first().press('PageUp');
        await this.tab.playwright.domSnapshot();
        observation = await this.observeText(root, step.arguments.expected_text);
      }
      return observation;
    }
    if (step.action === 'send_text') {
      const text = step.arguments.text;
      if (typeof text !== 'string' || !text.includes(step.arguments.marker)) throw new Error('Outgoing text must contain its campaign marker');
      const existing = await this.observeText(root, text);
      if (existing.match_count) return { ...existing, already_present: true };
      const composer = await this.one(root.getByRole('textbox'), 'conversation composer');
      const draft = await composer.innerText();
      if (draft.trim()) throw new Error('Existing draft preserved; the test will not overwrite it');
      await composer.click();
      await composer.pressSequentially(text);
      await this.tab.playwright.domSnapshot();
      if ((await composer.innerText()).replace(/\r\n/g, '\n') !== text) throw new Error('Draft does not match the authorized test message');
      const send = await this.one(root.getByRole('button', { name: 'Invia', exact: true }), 'send button');
      await send.click();
      await this.tab.playwright.domSnapshot();
      return { ...await this.observeText(root, text), already_present: false };
    }
    if (step.action === 'observe_reaction') {
      const observed = await this.observeText(root, step.arguments.expected_text);
      if (observed.match_count !== 1) return { ...observed, reaction: null };
      const reactions = await root.getByText(step.arguments.expected_text, { exact: true }).evaluateAll((elements, emoji) => {
        const matches = [];
        for (const element of elements) {
          const message = element.closest('[data-id]');
          if (!message) continue;
          const labels = Array.from(message.querySelectorAll('[aria-label], [alt]'))
            .map(item => (item.getAttribute('aria-label') || '') + ' ' + (item.getAttribute('alt') || ''));
          if (labels.some(label => label.includes(emoji))) matches.push(emoji);
        }
        return matches;
      }, step.arguments.emoji);
      return { ...observed, reaction: reactions.length ? step.arguments.emoji : null };
    }
    throw new Error('Browser action has no qualified adapter: ' + step.action);
  }
}
