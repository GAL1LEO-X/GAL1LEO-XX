'use strict';
const element = id => document.getElementById(id);
const csrf = document.body.dataset.csrf;
let activeRequest = null;
let errorSource = null, signingOut = false;
let restoreMaintenance = false;
let observationGeneration = 0, pendingMutations = 0, refreshing = false;
let pages = {history:{cursor:null, previous:[], next:null}, subscriptions:{cursor:null, previous:[], next:null}};
let currentOperations = [];
const retainedReceipts = new Map();
const stateNames = {running:"In progress", completed:"Completed", cancelled:"Cancelled", paused:"Paused", failed:"Recoverable error", failed_before_execution:"Not executed: invalid input", uncertain:"Outcome uncertain: verification required"};
const operationNames = {'history.pause':"Pause import",'history.resume':"Resume import",'history.cancel':"Cancel import",'subscription.disable':"Disable subscription",'instance.preview':"Preview instance",'instance.allocate':"Allocate instance",'instance.prepare':"Prepare instance",'instance.activate':"Activate instance",'instance.cancel':"Cancel preparation",'release.preview':"Prepare update",'release.activate':"Activate update",'backup.create':"Create backup",'backup.restore':"Restore backup"};
function showError(message, source = 'action') { errorSource = source; element('error').textContent = message; element('error').hidden = false; }
async function api(path, request) {
  const response = await fetch('/admin/api/' + path, request ? {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:JSON.stringify(request)} : {});
  const value = await response.json();
  if (response.status === 401) location.replace('/admin');
  if (!response.ok) throw new Error(value.message || value.error_code || "Request failed");
  return value;
}
function display(id, value) { element(id).textContent = JSON.stringify(value, null, 2); }
function actionButton(operation, target, label) {
  const button = document.createElement('button'); button.type = 'button'; button.textContent = label;
  button.addEventListener('click', () => confirmOperation(operation, target, {})); return button;
}
function renderRows(id, rows, kind) {
  const box = element(id); box.replaceChildren();
  if (!rows.length) {box.textContent = "No acquired items."; return;}
  for (const row of rows) {
    const card = document.createElement('article');
    const title = document.createElement('p'); title.className = 'record-title';
    title.textContent = kind === 'subscription' ? (row.active ? "Active" : "Inactive") + ' · ' + row.name : (stateNames[row.state] || row.state);
    const identity = document.createElement('p'); identity.className = 'record-id'; identity.textContent = row.id;
    card.append(title, identity);
    if (kind === 'subscription') {
      const delivery = document.createElement('p'); delivery.textContent = row.callback_acceptance_observed ? "HTTP receipt observed in history. Delivery to the final recipient is unverified." : "No HTTP acceptance in acquired history."; card.append(delivery);
      const expiry = document.createElement('p'); expiry.textContent = "Expires: " + new Date(row.expires * 1000).toISOString(); card.append(expiry);
    }
    if (kind === 'subscription' && row.active && !restoreMaintenance) card.append(actionButton('subscription.disable', row.id, "Disable subscription"));
    if (kind === 'history' && !['completed','cancelled'].includes(row.state) && !restoreMaintenance) {
      card.append(actionButton(row.state === 'running' ? 'history.pause' : 'history.resume', row.id, row.state === 'running' ? "Pause" : "Resume"));
      card.append(actionButton('history.cancel', row.id, "Cancel import"));
    }
    box.append(card);
  }
}
function renderOperations(rows) {
  currentOperations = rows;
  const merged = new Map(rows.map(row => [row.id, row]));
  for (const [id, receipt] of retainedReceipts) {
    const current = merged.get(id);
    // Keep directly observed receipts visible even if the next snapshot fails
    // or its bounded host receipt list does not contain this identifier.
    if (!current) merged.set(id, receipt);
    else if (['completed','failed_before_execution'].includes(receipt.state) && !['completed','failed_before_execution'].includes(current.state)) {
      merged.set(id, {...current, ...receipt});
    }
  }
  rows = Array.from(merged.values());
  const box = element('operations'); box.replaceChildren();
  if (!rows.length) {box.textContent = "No recorded administration operations."; return;}
  for (const row of rows) {
    const card = document.createElement('article');
    const title = document.createElement('p'); title.className = 'record-title'; title.textContent = (operationNames[row.operation] || row.operation) + ' · ' + (stateNames[row.state] || row.state);
    const target = document.createElement('p'); target.className = 'record-id'; target.textContent = row.target;
    if (row.affected_instances) target.textContent += " · Affected instances: " + row.affected_instances.join(', ');
    const date = document.createElement('p'); date.textContent = "Updated: " + row.updated_at;
    const details = document.createElement('details'); const label = document.createElement('summary'); label.textContent = "Receipt and identifier"; const data = document.createElement('pre'); data.textContent = JSON.stringify(row,null,2); details.append(label,data); card.append(title,target,date,details);
    if (row.operation === 'instance.cancel' && row.state === 'completed') {
      const retained = document.createElement('p'); retained.textContent = "Attempt resources cancelled. Allocation and journals are retained: the instance name cannot be reused automatically."; card.append(retained);
    }
    if (row.reconciled_by) {
      const recovery = document.createElement('p'); recovery.textContent = "Recovery recorded in operation " + row.reconciled_by + ". The original outcome remains separate."; card.append(recovery);
    }
    if ((row.approval || row.delegated) && ['running','uncertain'].includes(row.state) && !row.reconciled_by) {
      const read = document.createElement('button'); read.type = 'button'; read.textContent = "Check server receipt";
      read.addEventListener('click', async () => {
        read.disabled = true;
        try {
          const result = await api('operations/' + row.id);
          rememberReceipt(result);
          await refresh();
          element('notice').textContent = result.observation_error_code ? "Receipt unavailable. Keep identifier " + row.id + '.' : "Receipt " + row.id + ': ' + (stateNames[result.state] || result.state);
        } catch (error) {showError(error.message);} finally {read.disabled = false;}
      });
      card.append(read);
    }
    box.append(card);
  }
}
function rememberReceipt(row) {
  const previous = retainedReceipts.get(row.id);
  if (!previous || !['completed','failed_before_execution'].includes(previous.state)) retainedReceipts.set(row.id, row);
  if (retainedReceipts.size > 500) retainedReceipts.delete(retainedReceipts.keys().next().value);
  renderOperations(currentOperations);
}
function renderHostActions(actions) {
  const box = element('host-actions'); box.replaceChildren();
  if (!actions.length) {box.textContent = "No approved administration operations for this access."; return;}
  for (const action of actions) {
    const row = document.createElement('li');
    const title = document.createElement('p'); title.textContent = operationNames[action.operation] || action.operation; row.append(title);
    if (action.approval) {
      const description = document.createElement('p'); description.className = 'operation-description'; description.textContent = action.description; row.append(description);
      const impact = document.createElement('p'); impact.textContent = (action.scope === 'installation' ? "Shared operation. " : '') + "Affected instances: " + action.affected_instances.join(', ') + ". Target: " + action.target + '.'; row.append(impact);
      const approval = document.createElement('p'); approval.className = 'record-id'; approval.textContent = "Approval: " + action.approval; row.append(approval);
      if (action.available) {
        const button = document.createElement('button'); button.type = 'button'; button.textContent = "Confirm operation";
        button.addEventListener('click', () => confirmOperation(action.operation, action.target, {approval:action.approval}, description.textContent + ' ' + impact.textContent)); row.append(button);
      } else {const used = document.createElement('p'); used.textContent = "Approval unavailable. Inspect the operation receipt."; row.append(used);}
    } else {const reason = document.createElement('p'); reason.textContent = action.reason === 'broker_unavailable' ? "Broker unreachable; no new operations available." : "Administration channel not configured."; row.append(reason);}
    box.append(row);
  }
}
function renderConnection(value) {
  const labels = {
    activation_required:"Phone access disabled: wait for administrative activation of this instance.",
    connected:"Phone connected. An existing active session is preserved.",
    reconnection_required:"Connection interrupted: open the page and request a new code or QR to reconnect the phone.",
    phone_confirmation_required:"WhatsApp requires additional confirmation on the phone.",
    pairing_ready:"Ready for a temporary code or QR to approve on the phone.",
    provider_wait:"Phone state unverified or service starting. Refresh the observation before repeating a request."
  };
  element('activation-state').textContent = value.activation.required ? (value.activation.can_activate_from_panel ? "Activation required: an approved operation is available in Maintenance." : "Activation required; no approved operation is available for this instance.") : "Phone access and the connection page are enabled in the current configuration.";
  element('phone-state').textContent = (labels[value.stage] || labels.provider_wait) + " Observed: " + value.observed_at;
  const link = element('phone-link'); link.hidden = !value.pairing_url;
  if (value.pairing_url === '/connect') link.href = '/connect'; else link.removeAttribute('href');
  link.textContent = value.stage === 'reconnection_required' ? "Reconnect this phone" : value.stage === 'connected' ? "Check the connected phone" : "Connect this phone";
}
function readControls() {
  const busy = refreshing || pendingMutations > 0 || signingOut;
  element('refresh').disabled = busy;
  for (const kind of ['history','subscriptions']) {
    element(kind).setAttribute('aria-busy', String(busy));
    element(kind + '-previous').disabled = busy || !pages[kind].previous.length;
    element(kind + '-next').disabled = busy || !pages[kind].next;
  }
}
function renderPage(kind, rows, metadata, requested) {
  pages[kind] = {...requested, next:metadata.next_cursor};
  element(kind + '-page').textContent = "Page " + (requested.previous.length + 1) + ' · ' + rows.length +
    " items (maximum " + metadata.limit + '). ' + (metadata.next_cursor ? "More items on the next page." : "End of the observed list.");
}
async function movePage(kind, forward) {
  if (refreshing || pendingMutations || signingOut) return;
  const current = pages[kind];
  if (forward ? !current.next : !current.previous.length) return;
  const next = forward ? {...current, cursor:current.next, previous:[...current.previous,current.cursor]} :
    {...current, cursor:current.previous.at(-1), previous:current.previous.slice(0,-1)};
  if (await refresh({...pages, [kind]:next}) && !element('confirmation').open) element(kind + '-page').focus();
}
async function refresh(requestedPages = pages) {
  if (pendingMutations || signingOut) return false;
  const generation = ++observationGeneration;
  refreshing = true; readControls();
  try {
    const query = new URLSearchParams();
    for (const kind of ['history','subscriptions']) if (requestedPages[kind].cursor) query.set(kind + '_cursor', requestedPages[kind].cursor);
    const [value, connection] = await Promise.all([api('status' + (query.size ? '?' + query : '')), api('connection')]);
    // Commit the complete observation only if neither a newer read nor a
    // mutation has superseded it. Failed/older requests cannot replace notices.
    if (generation !== observationGeneration || pendingMutations || signingOut) return false;
    restoreMaintenance = value.restore_maintenance === true;
    element('maintenance-notice').hidden = !restoreMaintenance;
    element('preview').querySelector('button[type="submit"]').disabled = restoreMaintenance;
    element('host-list-limit').hidden = !value.host_actions_truncated;
    element('host-receipt-limit').hidden = !value.host_receipts_truncated;
    element('instance').textContent = value.instance;
    const lastCheck = value.connection.connection_checked_epoch ? new Date(value.connection.connection_checked_epoch * 1000).toISOString() : "unavailable";
    element('summary').textContent = 'Backend ' + value.version + ' · schema ' + value.schema + " · acquired connection " + value.connection.connection + " · last check: " + lastCheck;
    display('diagnostics', value.connection);
    element('status-cards').replaceChildren(...[
      ["Connection", value.connection.connection_fresh ? "Recent observation" : "Observation absent or stale"],
      ["Uncertain outcomes requiring review", value.connection.uncertain_active ?? value.connection.uncertain_sends],
      ["Acknowledged historical uncertain outcomes", value.connection.uncertain_known_history ?? 0],
      ["Active subscriptions", value.connection.active_subscriptions],
      ["Archive coverage", "Complete history unverified"]
    ].map(([title, text]) => {const card = document.createElement('article'); const label = document.createElement('strong'); label.textContent=title; const detail=document.createElement('p'); detail.textContent=text; card.append(label,detail); return card;}));
    element('capability-note').textContent = (value.capability_observation === 'provider_contract_confirmed' ? "Provider extensions confirmed. " : "Provider extensions unconfirmed; support unverified. ") + "Panel sign-in does not establish MCP permissions. An active subscription does not prove delivery.";
    display('capabilities', value.capabilities); renderOperations(value.operations);
    renderRows('subscriptions', value.subscriptions, 'subscription'); renderRows('history', value.history, 'history');
    renderConnection(connection);
    renderHostActions(value.host_actions);
    for (const kind of ['history','subscriptions']) renderPage(kind, value[kind], value[kind + '_page'], requestedPages[kind]);
    element('notice').textContent = "Observation refreshed. Data belongs to the current instance; each server operation states its scope.";
    if (errorSource === 'status') {element('error').hidden = true; element('error').textContent = ''; errorSource = null;}
    return true;
  } catch (error) {
    if (generation === observationGeneration) {showError(error.message, 'status'); element('notice').textContent = "Observation not refreshed.";}
    return false;
  } finally {
    if (generation === observationGeneration) {refreshing = false; readControls();}
  }
}
function requestId() { return Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, '0')).join(''); }
function confirmOperation(operation, target, args, details = '') {
  activeRequest = {id:requestId(), operation, target, arguments:args, confirmation:''};
  element('confirmation-label').textContent = operation + ':' + target;
  element('confirmation-details').textContent = details;
  element('confirmation-input').value = ''; element('confirmation').showModal();
}
element('confirmation').addEventListener('close', async () => {
  if (element('confirmation').returnValue !== 'confirm' || !activeRequest) return;
  const request = activeRequest; activeRequest = null; request.confirmation = element('confirmation-input').value;
  pendingMutations++; observationGeneration++; refreshing = false; readControls();
  element('notice').textContent = "Operation in progress: " + request.id;
  let result, failure;
  try {
    result = await api('operations', request);
    rememberReceipt(result);
    element('error').hidden = true;
    if (request.operation === 'instance.preview') display('preview-result', result);
  } catch (error) {failure = error;}
  finally {pendingMutations--; observationGeneration++; readControls();}
  const refreshed = await refresh();
  if (failure) {
    showError(failure.message); element('notice').textContent = "Inspect the journal before repeating. Identifier: " + request.id;
  } else if (refreshed) {
    element('notice').textContent = "Operation " + result.id + ': ' + (stateNames[result.state] || result.state);
  }
});
element('preview').addEventListener('submit', event => {
  event.preventDefault();
  try {confirmOperation('instance.preview', element('slug').value, {
    installation:JSON.parse(element('profile').value), roster:element('roster').value.trim() ? JSON.parse(element('roster').value) : null,
    account:element('account').value, bridge:Number(element('bridge').value), gateway:Number(element('gateway').value)
  });} catch {showError("Invalid profile or roster JSON.");}
});
element('receipt-lookup').addEventListener('submit', async event => {
  event.preventDefault();
  const identifier = element('receipt-id').value;
  if (!/^[a-f0-9]{32}$/.test(identifier)) {showError("Invalid identifier."); return;}
  try {
    const result = await api('operations/' + identifier);
    rememberReceipt(result);
    await refresh();
    element('notice').textContent = "Receipt " + identifier + ': ' + (stateNames[result.state] || result.state);
  } catch (error) {showError(error.message);}
});
element('refresh').addEventListener('click', () => refresh());
for (const kind of ['history','subscriptions']) {
  element(kind + '-previous').addEventListener('click', () => movePage(kind, false));
  element(kind + '-next').addEventListener('click', () => movePage(kind, true));
}
element('logs-button').addEventListener('click', async () => {try {display('logs', await api('logs'));} catch (error) {showError(error.message);}});
element('logout').addEventListener('click', async () => {
  if (signingOut) return;
  signingOut = true; element('logout').disabled = true;
  observationGeneration++; refreshing = false; readControls();
  try {
    const response = await fetch('/connect/api/logout', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':csrf}, body:'{}'});
    if (response.ok || response.status === 401) {location.replace('/admin'); return;}
    throw new Error('LOGOUT_UNVERIFIED');
  } catch {
    // A lost response may follow a successful revocation. Verify, never replay.
    try {
      const state = await fetch('/admin/api/connection', {cache:'no-store'});
      if (state.status === 401) {location.replace('/admin'); return;}
      showError(state.ok ? "The session still appears active. Sign-out is unconfirmed." : "Sign-out outcome unverified. Reload the page to check the session.", 'logout');
    } catch {showError("Sign-out outcome unverified. Reload when the connection is available.", 'logout');}
  } finally {signingOut = false; element('logout').disabled = false; readControls();}
});
refresh();
