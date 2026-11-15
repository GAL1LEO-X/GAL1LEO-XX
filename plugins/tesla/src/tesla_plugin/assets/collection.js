/* Local estimate only. The server validates and recalculates every proposal. */
(() => {
  'use strict';
  const editor = document.getElementById('collection-editor');
  if (!editor) return;
  const rows = [...editor.querySelectorAll('.collection-field')];
  const selectedFields = document.getElementById('selected-fields');
  const categories = [...editor.querySelectorAll('.collection-category')];
  const search = document.getElementById('field-search');
  const selectedSearch = document.getElementById('selected-search');
  const hours = document.getElementById('active-hours');
  const collectionDuration = document.getElementById('collection-duration');
  const money = new Intl.NumberFormat('en-GB', {minimumFractionDigits: 2, maximumFractionDigits: 2});
  const count = new Intl.NumberFormat('en-GB');
  const output = (id, value) => { document.getElementById(id).textContent = value; };
  const initial = new Map(rows.map(row => [row, [...row.querySelectorAll('.interval, .resend')].map(input => input.value)]));
  const duration = seconds => {
    const parts = [];
    for (const [unit, singular, plural] of [[3600, "hour", "hours"], [60, "minute", "minutes"], [1, "second", "seconds"]]) {
      const n = Math.floor(seconds / unit);
      seconds %= unit;
      if (n) parts.push(`${n} ${n === 1 ? singular : plural}`);
    }
    return parts.join(' and ');
  };
  const normalize = value => value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLocaleLowerCase('en');
  function filterCatalog() {
    const query = normalize(search.value.trim());
    const selectedQuery = normalize(selectedSearch.value.trim());
    let found = 0, selectedFound = 0;
    for (const row of rows) {
      const selected = row.querySelector('[name="field"]').checked;
      const text = normalize(row.querySelector('.field-overview').textContent+' '+row.querySelector('.field-description').textContent+' '+row.dataset.category);
      row.hidden = !text.includes(selected ? selectedQuery : query);
      if (!selected && !row.hidden) found++;
      if (selected && !row.hidden) selectedFound++;
    }
    for (const group of categories) {
      const remaining = [...group.querySelectorAll('.collection-field')];
      group.hidden = !remaining.some(row => !row.hidden);
      if (query && !group.hidden) group.open = true;
    }
    output('catalog-search-status', query ? `${found} fields match the search; check the listed requirements.` : '');
    output('selected-search-status', selectedQuery ? `${selectedFound} fields match the search. Selection and cost remain unchanged.` : '');
  }
  function update() {
    let selected = 0, signals = 0, continuous = 0, temporarySignals = 0;
    let valid = hours.checkValidity() && Number(hours.value) > 0 && Number(hours.value) <= 24;
    for (const row of rows) {
      const checked = row.querySelector('[name="field"]').checked;
      const interval = row.querySelector('.interval');
      const resend = row.querySelector('.resend');
      const delta = row.querySelector('.delta');
      for (const input of row.querySelectorAll('.field-timing input')) {
        input.disabled = !checked;
        input.setCustomValidity('');
      }
      interval.required = checked;
      const destination = checked ? selectedFields : categories.find(g => g.dataset.category === row.dataset.category).querySelector('.category-fields');
      if (row.parentElement !== destination) {
        const focused = row.contains(document.activeElement) ? document.activeElement : null;
        destination.append(row);
        if (focused) focused.focus({preventScroll: true});
      }
      if (!checked) continue;
      selected++;
      const i = Number(interval.value), r = resend.value ? Number(resend.value) : 0;
      if (r && r < i) resend.setCustomValidity("Resend must be at least the minimum interval.");
      if (delta && row.dataset.field === 'SelfDrivingMilesSinceReset' && Number(delta.value) < 1) {
        delta.setCustomValidity("This field requires a minimum change of at least 1 mile.");
      }
      const rowValid = [...row.querySelectorAll('.field-timing input')].every(input => input.checkValidity());
      valid = valid && rowValid;
      row.querySelector('.field-frequency').textContent = rowValid
        ? `On change: at most every ${duration(i)}. `+(r ? `Requested resend: ${duration(r)}.` : "Resend: Tesla default.")+(delta && delta.value ? ` Threshold: ${delta.value} ${row.dataset.deltaUnit}.` : '')
        : "Check timing and threshold for this field.";
      if (i > 0 && rowValid) {
        const included = row.querySelector(".includes").value.split(",").map(s => s.trim()).filter(Boolean);
        const perDay = h => (1 + included.length) * (1 + Math.ceil(h * 3600 / i) + (r ? Math.ceil(h * 3600 / r) : 0));
        signals += 30 * perDay(Number(hours.value));
        continuous += 30 * perDay(24);
        if (collectionDuration.value) temporarySignals += perDay(Number(collectionDuration.value) / 3600);
        const price = 30 * perDay(Number(hours.value)) / 150000;
        row.querySelector('.field-estimate output').textContent = hours.checkValidity() ? (price > 0 && price < 0.005 ? '< 0.01' : money.format(price)) : '—';
      } else {
        row.querySelector('.field-estimate output').textContent = '—';
      }
    }
    for (const group of categories) {
      const boxes = rows.filter(r => r.dataset.category === group.dataset.category).map(r => r.querySelector('[name="field"]'));
      group.querySelector('summary > span').textContent = `${boxes.filter(b => b.checked).length} / ${boxes.length} selected`;
    }
    document.getElementById('no-selected-fields').hidden = !!selected;
    selectedSearch.closest('label').hidden = selected <= 12;
    if (selected <= 12) selectedSearch.value = '';
    filterCatalog();
    output('selected-count', count.format(selected));
    output('signal-count', valid ? count.format(signals) : '—');
    output('monthly-cost', valid ? money.format(signals / 150000) : '—');
    output('editing-cost', valid ? money.format(signals / 150000) : '—');
    output('continuous-cost', valid ? money.format(continuous / 150000) : '—');
    output('temporary-estimate', !collectionDuration.value ? "Continue until a confirmed change." : valid
      ? `${temporarySignals > 0 && temporarySignals / 150000 < 0.005 ? '< 0.01' : money.format(temporarySignals / 150000)} estimated USD for ${duration(Number(collectionDuration.value))}, assuming a continuously awake vehicle. Other costs excluded; not a spending cap.`
      : "Check the proposal to estimate the window cost.");
    output('calculator-status', !valid ? "Check hours and selected field intervals." : !selected
      ? "No fields selected. Use Pause collection to stop an active profile."
      : "Estimate updated in the browser. No change sent to Tesla.");
    editor.querySelector('[value="configure"]').disabled = editor.dataset.locked === 'true' || !valid || !selected;
    editor.querySelector('[value="estimate"]').disabled = !valid || !selected;
    for (const button of editor.querySelectorAll('[data-tempo]')) button.disabled = !selected || (!valid && button.dataset.tempo !== 'reset');
  }
  for (const selector of ['.collection-bulk', '.collection-tempo', '.collection-search']) editor.querySelector(selector).hidden = false;
  const customized = () => {
    output('proposal-name', "Custom · form changes");
    const impact = document.getElementById('trigger-impact');
    if (impact) {
      impact.querySelector('.impact-status').textContent = "Proposal changed: use Calculate estimate or Review configuration to reassess the impact on events.";
      impact.querySelector('.impact-details').hidden = true;
    }
  };
  for (const button of editor.querySelectorAll('[data-select]')) {
    button.addEventListener('click', () => {
      for (const row of rows) {
        const box = row.querySelector('[name="field"]');
        if (!box.disabled) box.checked = button.dataset.select === 'all';
      }
      customized();
      update();
    });
  }
  for (const button of editor.querySelectorAll('[data-tempo]')) {
    button.addEventListener('click', () => {
      for (const row of rows.filter(r => r.querySelector('[name="field"]').checked)) {
        [...row.querySelectorAll('.interval, .resend')].forEach((input, index) => {
          if (button.dataset.tempo === 'reset') input.value = initial.get(row)[index];
          else if (input.value) input.value = Math.max(1, Math.min(86400, Math.ceil(Number(input.value) * Number(button.dataset.tempo))));
        });
      }
      customized();
      update();
      output('tempo-status', button.dataset.tempo === 'reset'
        ? "Loaded timing restored for selected fields. No change applied to the vehicle."
        : "Form timing updated and estimate recalculated. Limits are 1 second to 24 hours; check the listed frequencies for each field.");
    });
  }
  search.addEventListener('input', filterCatalog);
  selectedSearch.addEventListener('input', filterCatalog);
  for (const event of ['input', 'change']) editor.addEventListener(event, e => {
    if (e.target === search || e.target === selectedSearch) return;
    if (e.target !== hours) customized();
    update();
  });
  editor.addEventListener('invalid', e => {
    for (let group = e.target.closest('details'); group; group = group.parentElement.closest('details')) group.open = true;
  }, true);
  update();
})();
