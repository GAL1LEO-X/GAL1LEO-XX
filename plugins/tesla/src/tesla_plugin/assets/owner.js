/* Presentation only: open anchored disclosures and copy the one-time setup.
   No polling, vehicle requests, settings writes or persisted UI state. */
(() => {
  'use strict';
  // Age labels advance locally; no new observation or network read is implied.
  const loadedAt = performance.now();
  const observed = [...document.querySelectorAll('[data-sample-age]')];
  const assessments = [...document.querySelectorAll('[data-evidence-expires-in]')];
  function updateAges() {
    const elapsed = (performance.now() - loadedAt) / 1000;
    for (const item of observed) {
      const age = Number(item.dataset.sampleAge) + elapsed;
      const stale = age > Number(item.dataset.ageLimit);
      const quality = item.dataset.qualityLabel;
      const ago = age < 60 ? `${Math.floor(age)} s ago` : age < 3600 ? `${Math.floor(age / 60)} min ago` : `${Math.floor(age / 3600)} h ago`;
      item.querySelector('.observation-label').textContent = `${quality || (stale ? 'Historical' : 'Recent')} · ${ago}`;
      item.classList.toggle('is-stale', !!quality || stale);
    }
    for (const item of assessments) {
      if (elapsed <= Number(item.dataset.evidenceExpiresIn)) continue;
      for (const current of item.querySelectorAll('[data-evidence-current]')) current.hidden = true;
      for (const expired of item.querySelectorAll('[data-evidence-expired]')) expired.hidden = false;
    }
  }
  // A one-second local timer covers Gear's 15 s window without network polling.
  if (observed.length || assessments.length) window.setInterval(updateAges, 1000);
  document.addEventListener('visibilitychange', updateAges);
  window.addEventListener('pageshow', updateAges);
  const backToTop = document.querySelector('.back-to-top');
  if (backToTop) {
    const updateBackToTop = () => {backToTop.hidden = window.scrollY < 100;};
    window.addEventListener('scroll', updateBackToTop, {passive: true});
    updateBackToTop();
  }
  function revealAnchor() {
    let id;
    try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
    const target = document.getElementById(id);
    if (!target) return;
    const ownDetails = target.matches('details') ? target : target.querySelector(':scope > details');
    if (ownDetails) ownDetails.open = true;
    for (let parent = target.parentElement; parent; parent = parent.parentElement) {
      if (parent.matches('details')) parent.open = true;
    }
    if (id !== 'inizio') target.scrollIntoView();
  }
  window.addEventListener('hashchange', revealAnchor);
  revealAnchor();
  for (const button of document.querySelectorAll('[data-copy-setup]')) {
    button.hidden = false;
    button.addEventListener('click', async () => {
      const text = document.getElementById(button.dataset.copySetup);
      const status = document.getElementById(button.dataset.copySetup+'-status');
      try {
        await navigator.clipboard.writeText(text.value);
        status.textContent = 'Copiato. Incollalo nella chat con il plugin TESLA.';
      } catch {
        text.focus(); text.select();
        status.textContent = 'Testo selezionato: copialo e incollalo nella chat con il plugin TESLA.';
      }
    });
  }
})();
