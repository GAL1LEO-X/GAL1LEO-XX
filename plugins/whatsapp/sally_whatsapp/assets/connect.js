(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const csrf = document.body.dataset.csrf;
  const requests = new AbortController();
  let busy = false, stopped = false, activeMode = null, ready = false, polling = false;
  let qrRevision = null, qrLoadedAt = 0, generation = 0, timer = null, errorSource = null;
  const labels = {
    PREPARED: ["Connection not activated.", "The page is accessible; phone access remains disabled until administrative activation."],
    WORKING: ["WhatsApp connected.", "The phone is available for this profile."],
    STOPPED: ["Ready to connect.", "Choose a temporary code or QR."],
    STARTING: ["Connection starting…", "Wait a few seconds without repeating the request."],
    SCAN_QR_CODE: ["Waiting for the phone.", "Complete the connection in WhatsApp on your phone."],
    FAILED: ["The connection was interrupted.", "Try again with a new code or QR."],
    PASSKEY_REQUIRED: ["Phone verification required.", "Open WhatsApp and complete verification before continuing."],
    PASSKEY_CONFIRMATION_REQUIRED: ["Confirm on the phone.", "Compare and confirm the code shown in WhatsApp."],
    UNKNOWN: ["State not available yet.", "Wait or check again shortly."]
  };
  function error(message, source = null) {
    $('error').textContent = message; $('error').hidden = !message; errorSource = source;
  }
  function status(title, detail) { $('status-title').textContent = title; $('status-detail').textContent = detail; }
  function clearCodes() {
    activeMode = null; qrRevision = null; qrLoadedAt = 0;
    $('code-result').hidden = true; $('qr-result').hidden = true;
    $('pairing-code').textContent = ''; $('qr-image').removeAttribute('src');
  }
  function refreshQr(data, force = false) {
    if (stopped || activeMode !== 'qr' || data.state !== 'SCAN_QR_CODE') return;
    const revision = data.qr_revision || '';
    // A bounded refresh also recovers when a status webhook was missed.
    if (force || revision !== qrRevision || Date.now() - qrLoadedAt >= 15000) {
      qrRevision = revision; qrLoadedAt = Date.now();
      $('qr-image').src = '/connect/qr?v=' + qrLoadedAt;
    }
  }
  function controls() {
    for (const id of ['code-button', 'qr-button', 'qr-refresh']) $(id).disabled = busy || !ready || stopped;
    $('logout').disabled = busy;
    $('status-retry').disabled = busy || polling;
    $('pairing').setAttribute('aria-busy', String(busy));
  }
  function render(data) {
    const connected = data.connected === true;
    status(...(labels[data.state] || labels.UNKNOWN));
    $('status').classList.toggle('connected', connected);
    $('status').classList.toggle('warning', ['FAILED', 'PASSKEY_REQUIRED', 'PASSKEY_CONFIRMATION_REQUIRED'].includes(data.state));
    $('pairing').hidden = connected || data.activation_required === true;
    $('activation-required').hidden = data.activation_required !== true;
    $('connected').hidden = !connected;
    ready = ['STOPPED', 'SCAN_QR_CODE', 'FAILED'].includes(data.state);
    $('status-retry').hidden = connected || ready;
    if (data.state !== 'SCAN_QR_CODE') clearCodes();
    else refreshQr(data);
    if (connected) {
      $('page-step').textContent = "03 · CONFIRM";
      $('page-title').textContent = "WhatsApp is connected.";
      $('page-intro').textContent = "The phone connection to this profile is active.";
      stopped = true;
    }
    controls();
  }
  function failed(err, source) {
    if (err.name === 'AbortError') return;
    if (err.status === 401) {
      stopped = true; ready = false; generation++; clearCodes(); clearTimeout(timer);
      $('pairing').hidden = true; $('connected').hidden = true;
      $('status-retry').hidden = true; $('session-actions').hidden = true;
      $('session-expired').hidden = false;
      $('access-badge').textContent = "Sign-in required"; $('access-badge').classList.remove('verified');
      status("The page session ended.", err.message);
      $('status').classList.remove('connected'); $('status').classList.add('warning');
      error('');
    } else {
      error(err.message, source);
      if (source === 'status') $('status-retry').hidden = false;
      else $('error').focus();
    }
    controls();
  }
  async function api(path, data) {
    const options = {cache: 'no-store', credentials: 'same-origin', signal: requests.signal};
    if (data !== undefined) Object.assign(options, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf}, body: JSON.stringify(data)});
    let response, value;
    try {
      response = await fetch('/connect/api/' + path, options);
      value = await response.json();
    } catch (err) {
      if (err.name === 'AbortError') throw err;
      throw new Error("The service is unreachable. Check your connection and try again.");
    }
    if (!response.ok) {
      const err = new Error(typeof value.error === 'string' ? value.error : "Operation failed. Try again.");
      err.status = response.status;
      throw err;
    }
    return value;
  }
  async function pair(mode) {
    if (busy || stopped || !ready) return;
    busy = true; generation++; controls(); error(''); clearCodes();
    const button = $(mode === 'code' ? 'code-button' : 'qr-button');
    const label = button.textContent;
    button.textContent = "Request in progress…";
    try {
      const data = await api('pair', {mode, phone: mode === 'code' ? $('phone').value : ''});
      render(data);
      if (!stopped && data.state === 'SCAN_QR_CODE') {
        if (data.code) { activeMode = 'code'; $('pairing-code').textContent = data.code; $('code-result').hidden = false; $('code-result').focus(); }
        if (data.qr_url) { activeMode = 'qr'; $('qr-result').hidden = false; refreshQr(data, true); $('qr-result').focus(); }
      }
    } catch (err) { failed(err, 'pair'); }
    finally { button.textContent = label; busy = false; controls(); }
  }
  async function poll() {
    if (polling) return;
    clearTimeout(timer);
    const current = generation;
    if (!busy && !stopped) {
      polling = true; controls();
      try {
        const data = await api('status');
        // A response requested before a new pairing action cannot clear its code.
        if (current === generation && !stopped) {
          render(data);
          if (errorSource === 'status') error('');
        }
      } catch (err) { if (current === generation && !stopped) failed(err, 'status'); }
      finally { polling = false; controls(); }
    }
    if (!stopped) timer = setTimeout(poll, 5000);
  }
  $('code-form').addEventListener('submit', event => { event.preventDefault(); pair('code'); });
  $('qr-button').addEventListener('click', () => pair('qr'));
  $('qr-refresh').addEventListener('click', () => refreshQr({state: 'SCAN_QR_CODE', qr_revision: qrRevision}, true));
  $('status-retry').addEventListener('click', poll);
  $('qr-image').addEventListener('error', () => {
    if (activeMode === 'qr') error("QR unavailable or expired. Check status and try again.", 'pair');
  });
  $('logout').addEventListener('click', async () => {
    if (busy) return;
    busy = true; generation++; controls(); clearCodes();
    let verifyStatus = false;
    try { await api('logout', {}); location.assign('/connect'); }
    catch (err) {
      failed(err, 'logout');
      // A lost response may mean logout succeeded. Check the session without
      // repeating the POST, including when WORKING had stopped normal polling.
      if (err.name !== 'AbortError' && err.status !== 401) { stopped = false; verifyStatus = true; }
    }
    finally { busy = false; controls(); if (verifyStatus) poll(); }
  });
  window.addEventListener('pagehide', () => {
    // Do not leave pairing credentials in a history/bfcache snapshot.
    stopped = true; generation++; clearTimeout(timer); clearCodes();
    $('phone').value = ''; requests.abort();
  });
  window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
  poll();
})();
