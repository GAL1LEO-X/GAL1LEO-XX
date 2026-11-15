"""Server-rendered, keyboard-accessible trigger controls. No client state copy."""
from html import escape
from urllib.parse import urlencode

from .ui import icon
from .errors import TeslaError
from .trigger_catalog import FIELD_MAP
from .collection_catalog import field_info

READINESS = {"permission_required": 'Location permission required',
             "rule_required": "No enabled rule: configure or re-enable the condition",
             "collection_unverified": 'Collection needs verification: a requested or saved profile does not prove application',
             "collection_paused": 'Collection paused or absent',
             "collection_missing": 'Required collection missing',
             "data_missing": 'Collection configured, waiting for required data',
             "data_invalid": 'Invalid received data',
             "data_stale": 'Received data is too old for this rule',
             "data_incoherent": 'Observation timestamps are not close enough for this rule',
             "timing_warning": 'Data available; collection timing may leave assessment gaps',
             "inputs_available": 'Data requirements met at the latest check'}

READINESS_SHORT = {"permission_required": 'Permission required', "rule_required": 'Condition requires configuration',
                   "collection_unverified": 'Collection needs verification', "collection_paused": 'Collection paused',
                   "collection_missing": 'Collection is missing required fields', "data_missing": 'Waiting for data',
                   "data_invalid": 'Invalid value', "data_stale": 'Field to refresh',
                   "data_incoherent": 'Inconsistent timestamps', "timing_warning": 'Timing needs review',
                   "inputs_available": 'Available data'}


def readiness_text(item):
    info = item["readiness"]
    text = ('Enabled · ' if item["enabled"] else 'Not selected · ')+READINESS[info["status"]]
    if info["missing_fields"]:
        text += '. Missing fields: '+", ".join(field_info(FIELD_MAP[f])["label"] for f in info["missing_fields"])
    if info["customer_alerts_missing"]:
        text += '. Tesla driver alerts excluded from collection'
    if item["id"] == "event:data_stale":
        text += '. May report previously observed data becoming stale even after collection is paused'
    return text

CATEGORIES = {'Primary': 'Primary events', "Charging": 'Charging', "Powertrain": 'Battery and powertrain',
              "Vehicle State": 'Vehicle state', "Climate": 'Climate', "Service": 'Maintenance',
              "Safety": 'Safety', "Vehicle Configuration": 'Vehicle configuration', "Location": 'Location',
              "Driving": 'Driving', "Media": 'Media', "User Preference": 'Preferences', 'Rules': 'Rules and conditions'}
FIELD_LABELS = {"InsideTemp": 'Cabin temperature', "OutsideTemp": 'Outside temperature', "BatteryLevel": 'Battery level',
                "Locked": 'Vehicle locking', "Location": 'Vehicle coordinates', "Version": 'Software version',
                "DetailedChargeState": 'Charging state', "ChargeLimitSoc": 'Charge limit', "VehicleSpeed": 'Speed',
                "Odometer": 'Odometer', "DriverSeatOccupied": 'Driver seat occupied', "Gear": 'Selected gear'}
RULE_LABELS = {"battery_low": 'Battery · threshold', "charging": 'Charging · state changes',
               "unlocked_parked": 'Open vehicle · parked dwell time', "trip": 'Trips · departure and arrival',
               "software": 'Software · version change', "stale": 'Data · time without updates',
               "geofence": 'Location · area entry and exit', "threshold": 'Custom threshold',
               "field_changed": 'Custom change'}
RULE_PARAMETERS = {"max_age_seconds": 'Maximum sample age (seconds)', "max_gap_seconds": 'Maximum observation gap (seconds)',
                   "dwell_seconds": 'Condition dwell time (seconds)', "hysteresis": 'Threshold hysteresis',
                   "threshold": 'Threshold', "latitude": 'Latitude', "longitude": 'Longitude', "radius_m": 'Radius (metres)'}


def rule_form_config(rule, form):
    config = dict(rule["config"])
    try:
        for key in RULE_PARAMETERS:
            if key in config:
                config[key] = float(form.get(key, ""))
        for key in ("field", "direction"):
            if key in config:
                config[key] = form.get(key, config[key])
    except (ValueError, TypeError):
        raise TeslaError("INVALID_ARGUMENT", 'Check the numeric rule parameters.') from None
    return config


def hidden(name, value):
    return f'<input type="hidden" name="{name}" value="{escape(str(value), quote=True)}">'


def render(view, csrf, base, *, saved=False):
    action = base+"/owner/triggers/"+view["vehicle_ref"]
    fields = hidden("csrf", csrf)+hidden("revision", view["revision"])
    body = ""
    body += '<div class="settings-route"><strong>Your notifications</strong><a href="'+base+'/owner/collection/'+view["vehicle_ref"]+'">Tesla data and cost →</a></div>'
    if saved:
        body += '<p class="trigger-feedback" role="status">Selection saved. The panel and ChatGPT use the same settings.</p>'
    body += '<section class="trigger-intro"><p>One selection, shared with ChatGPT. Save here or ask in chat: the same choices appear in both. Collection and Tesla costs remain unchanged.</p></section>'
    selected = [i for i in view["items"] if i["enabled"] and not i["id"].startswith("rule:")]
    attention = sum(i["operational"]["status"] != "ready" for i in selected)
    main_selected = [i for i in selected if i["id"].startswith("event:")]
    body += '<section class="trigger-readiness"><div class="readiness-metrics"><span><strong>'+str(len(selected))+'</strong> selected</span><span><strong>'+str(len(selected)-attention)+'</strong> ready at the latest check</span><span><strong>'+str(attention)+'</strong> pending or needs verification</span></div>'
    connection = view["delivery_connection"]
    label, explanation = {
        "not_connected": ('Connect ChatGPT event delivery', 'Your selections are saved. Only the initial connection allowing ChatGPT to receive events is missing.'),
        "partial": ('Connection incomplete', 'The current connection covers only some events. Extend it once while keeping saved selections.'),
        "selected_only": ('Extend connection to future selections', 'Selected events are covered. Extend the connection once to also cover future selections automatically.'),
        "shared": ('Event connection active', 'Changes saved here or in chat apply to the same connection. Only selected events are forwarded. Verify processing and messages in the ChatGPT host.')
    }[connection["state"]]
    body += '<div class="trigger-connection">'+icon("shield")+'<div><strong>'+label+'</strong><p>'+explanation+'</p>'
    if connection["setup_required"]:
        prompt = ('Connect native event delivery for the TESLA plugin for '+view["vehicle_ref"]+'. Read tesla_list_triggers and use delivery_connection.subscription_plan to cover all authorized types: the server forwards only selected events. Reuse or update the existing automation without duplication. Do not change selectors, rules or collection, and do not send vehicle commands. On receipt, read tesla_get_event, deduplicate and assess whether to notify me. Use native events only, without periodic checks; report unavailable host tools. Confirm the connection only after verification, distinguishing it from actual delivery.')
        body += '<details class="connection-setup"><summary>Complete initial connection</summary><p>This step chooses the destination chat, not the events. Afterwards, manage selections here or in chat without repeating them. The connection remains active while ChatGPT renews it and permissions remain valid.</p>'
        body += '<label for="event-setup-prompt">Request ready for the TESLA chat</label><textarea id="event-setup-prompt" readonly rows="4">'+escape(prompt)+'</textarea><button type="button" class="button button-secondary" data-copy-setup="event-setup-prompt" hidden>Copy request</button><p id="event-setup-prompt-status" role="status"></p></details>'
    body += '</div></div>'
    access = view["delivery_access"]
    body += '<details class="delivery-access-settings"><summary>Additional access check · '+('on event' if access['automatic'] else 'disabled')+'</summary>'
    body += '<p>Collection may already keep vehicle access verified. If verification expires, this check can renew it when an event is pending delivery. The same setting can be changed in chat.</p>'
    body += '<form method="post" action="'+action+'">'+fields+hidden("category", "delivery_access")
    body += '<label class="trigger-option"><input type="checkbox" name="automatic_access_checks" value="true"'+(' checked' if access['automatic'] else '')+'><span>Automatically check access before delivery when necessary</span></label>'
    body += '<p class="field-help">Reads the vehicle list without waking the vehicle or changing collection. Reuses verification for 5 minutes; at most 3 attempts per account in 15 minutes and up to 3 pages per attempt. No calls without pending events. The catalogue classifies this REST read as unbilled; Tesla billing remains authoritative and is separate from the streaming estimate.</p>'
    body += '<button class="button button-secondary">Save access check</button></form>'
    if access['last_result']:
        outcome = {'checking': 'in progress', 'verified': 'successful', 'blocked': 'unsuccessful'}.get(access['last_result'], 'needs verification')
        body += '<p class="field-help">Last check: '+outcome+'.'
        if access['retry_after']:
            body += ' Next attempt allowed after '+escape(access['retry_after'].replace('T', ' ').replace('Z', ' UTC'))+', only with a valid queued event.'
        body += '</p>'
    body += '</details>'
    body += '<details class="state-evidence"><summary>Selected and ready are different states</summary><p>Applied collection, valid fresh data, rules, authorization and a subscription are required. A checkbox never activates collection.</p>'
    if view["collection"]["checked_at"] is not None:
        body += '<p class="field-help">Latest collection check: '+str(int(view["collection"]["age_seconds"]//60))+' minutes ago. This check uses cached evidence without contacting Tesla.</p>'
    body += '</details>'
    if main_selected:
        query = urlencode([("for_trigger", i["id"]) for i in main_selected])
        body += '<a class="text-link" href="'+base+'/owner/collection/'+view["vehicle_ref"]+'?'+escape(query, quote=True)+'#proposta">Review data and cost for primary events →</a>'
    body += '</section>'
    profiles = {"recommended": 'Recommended', "all": 'All available', "none": 'None', "custom": 'Custom'}
    body += '<section class="preset-section event-presets"><h2>Events that matter to you</h2><p>Current selection: <strong>'+profiles[view["selection_preset"]]+'</strong>. Choose a profile or customize it below.</p><div class="preset-grid">'
    for preset, title, description in (
        ("recommended", 'Recommended', 'Low battery, interrupted or completed charging, an open vehicle while parked, vehicle alerts and software changes. Excludes trips and changes to individual fields.'),
        ("all", 'All available', 'Enable permitted events, individual fields and existing rules. This can produce many events; custom conditions must already be configured.'),
        ("none", 'None', 'Disable events sent to ChatGPT. Data collection remains unchanged: use Data collection to pause it.')):
        body += '<article class="preset-card'+(' preset-recommended' if preset == 'recommended' else '')+'"><form method="post" action="'+action+'">'+fields+hidden("category", "preset")+hidden("preset", preset)+'<button class="button button-secondary">Use '+title.lower()+'</button></form><details><summary>What is included</summary><p>'+description+'</p></details></article>'
    body += '</div><p class="field-help">This preset replaces the selection. It preserves thresholds, conditions and batching. Collection remains unchanged.</p></section>'
    if not view["tesla_connected"]:
        body += '<p class="trigger-feedback">Tesla connection needs recovery. You can inspect selection and disable triggers; enabling them requires reconnecting the account.</p>'
    elif not view["membership_fresh"]:
        message = {'live_disabled': 'Tesla requests are disabled: automatic verification cannot start.',
                   'tesla_scope_required': 'Verification requires Tesla vehicle-list permission: reconnect the account with that permission.',
                   'pricing_review_required': 'The authorization-read cost needs review. Automatic checking is blocked.'}.get(access['blocked_reason'])
        message = message or ('Access will be checked when a valid event is pending delivery.' if access['automatic'] else 'Delivery awaits a recent access check. Refresh vehicles or enable the automatic event-driven check above.')
        body += '<p class="trigger-feedback">'+message+'</p>'
    advanced = ""
    if selected:
        advanced += '<a class="button button-secondary" href="'+base+'/owner/collection/'+view["vehicle_ref"]+'?for_trigger=selected#proposta">Review collection for all selected events and fields</a><p class="field-help">Selecting all fields may include 239 data fields and substantially increase cost. Always show the estimate before confirmation.</p>'
    counts = view["deliveries_last_24h"]
    pending = sum(view["delivery_counts"].get(k, 0) for k in ("pending", "sending"))
    advanced += '<div class="trigger-delivery-stats"><span>Queued: <strong>'+str(pending)+'</strong></span><span>Accepted by the recipient in the last 24 hours: <strong>'+str(counts.get("accepted", 0))+'</strong></span><span>Expired or failed in the last 24 hours: <strong>'+str(counts.get("expired", 0)+counts.get("failed", 0))+'</strong></span></div>'
    advanced += '<p class="field-help">ChatGPT processing and notification cannot be observed by this panel. Check runs and messages in the destination chat or dot; missing data here does not indicate failure.</p>'
    advanced += '<p class="trigger-cost-note">With additional selected fields: up to '+f'{view["additional_batch_envelopes_per_hour_max"]:g}'+' change batches/hour, in addition to primary events. This is a frequency limit, not a spending forecast: ChatGPT processing, traffic and storage depend on usage. Recipient acceptance does not prove a notification was displayed.</p>'
    advanced += '<form class="trigger-batching" method="post" action="'+action+'">'+fields+hidden("category", "batching")
    advanced += '<label>Batch field changes<select name="batch_seconds">'
    for value in sorted({10, 30, 60, 120, 300, view["batch_seconds"]}):
        advanced += f'<option value="{value}"'+(' selected' if value == view["batch_seconds"] else '')+f'>Every {value} seconds</option>'
    advanced += '</select></label><button class="button button-secondary">Save interval</button><p>Primary events are sent when detected. History also retains intermediate observations of batched fields.</p></form>'
    groups = {}
    for item in view["items"]:
        groups.setdefault(item["category"], []).append(item)
    for category, items in groups.items():
        count = sum(item["enabled"] for item in items)
        if category == 'Primary':
            items = sorted(items, key=lambda item: not item["enabled"])
        label = CATEGORIES.get(category, category)
        group = ""
        group += '<details class="trigger-group"'+(' open' if category == 'Primary' else '')+'><summary><span>'+escape(label)+'</span><small>'+f'{count} / {len(items)} selected</small></summary>'
        group += '<form method="post" action="'+action+'">'+fields+hidden("category", category)+'<div class="trigger-grid">'
        for index, item in enumerate(items):
            if category == 'Primary' and index == count:
                if not count:
                    group += '<p class="field-help">No primary events selected. Choose a preset above or open other events.</p>'
                group += '</div><details class="other-events"><summary>Other primary events · '+str(len(items)-count)+' available</summary><div class="trigger-grid">'
            title = RULE_LABELS.get(item["label"], item["label"]) if category == 'Rules' else FIELD_LABELS.get(item["label"], item["label"])
            detail = readiness_text(item)
            if item["id"].startswith("event:") and item["source_fields"]:
                detail += " · "+", ".join(item["source_fields"])
            checked = ' checked' if item["enabled"] else ''
            # A previously enabled, now-withheld field can still be turned off.
            disabled = ' disabled' if (not item["available"] or not view["tesla_connected"]) and not item["enabled"] else ''
            short = item["operational"]["label"]
            group += '<div class="trigger-item" data-trigger="'+escape(item["id"], quote=True)+'"><label class="trigger-option"><input type="checkbox" name="enabled" value="'+escape(item["id"], quote=True)+'"'+checked+disabled+'><span><strong>'+escape(title)+'</strong><small>'+escape(short)+'</small>'
            if item["id"].startswith("field:") and title != item["label"]:
                group += '<small class="trigger-field-name">'+escape(item["label"])+'</small>'
            group += '</span></label>'
            group += '<details class="trigger-evidence"><summary>Requirements and details</summary><p>'+escape(detail)+'</p>'
            group += '<p class="trigger-next-step">'+escape(item["operational"]["next_step"])+'</p>'
            if item["enabled"] and not item["id"].startswith("rule:") and not item["subscribed"]:
                group += '<p class="trigger-delivery-note">Receiving this event requires the ChatGPT connection shown above.</p>'
            if item["available"] and item["readiness"]["paths"] and item["readiness"]["status"] != "inputs_available":
                url = base+'/owner/collection/'+view["vehicle_ref"]+'?'+urlencode({"for_trigger": item["id"]})+'#proposta'
                group += '<a class="trigger-repair" href="'+escape(url, quote=True)+'">Review required data and cost<span class="sr-only"> · '+escape(title)+'</span> →</a>'
            group += '</details></div>'
        group += '</div>'
        if category == 'Primary' and count < len(items):
            group += '</details>'
        group += '<div class="trigger-buttons"><button class="button button-primary" name="selection" value="save">Save selection</button><button class="button button-secondary" name="selection" value="all">Enable category</button><button class="button button-quiet" name="selection" value="none">Disable category</button></div></form></details>'
        if category == 'Primary':
            body += group
        else:
            advanced += group
    advanced += '<section class="rule-settings"><h2>Thresholds and conditions</h2><p>Edit existing rules here or explicitly ask ChatGPT. Saving preserves the enabled or disabled state of each rule.</p>'
    for item in groups.get('Rules', []):
        if not item["available"] or item.get("config") is None:
            continue
        advanced += '<details class="trigger-rule-details"><summary>'+escape(RULE_LABELS.get(item["label"], item["label"]))+'</summary><form method="post" action="'+action+'">'+fields+hidden("category", "rule")+hidden("rule_id", item["id"][5:])+'<div class="rule-fields">'
        for key, value in item["config"].items():
            if key in RULE_PARAMETERS:
                advanced += '<label>'+RULE_PARAMETERS[key]+'<input name="'+key+'" type="number" step="any" value="'+escape(str(value), quote=True)+'" required></label>'
            elif key == "field":
                advanced += '<label>Observed field<select name="field">'
                for name, spec in sorted(FIELD_MAP.items()):
                    if spec["catalog_status"] == "DOCUMENTED":
                        advanced += '<option value="'+name+'"'+(' selected' if name == value else '')+'>'+escape(FIELD_LABELS.get(name, name))+'</option>'
                advanced += '</select></label>'
            elif key == "direction":
                advanced += '<label>Direction<select name="direction">'+''.join('<option value="'+v+'"'+(' selected' if value == v else '')+'>'+label+'</option>' for v, label in (("below", 'Below threshold'), ("above", 'Above threshold')))+'</select></label>'
        advanced += '</div><p class="field-help">Low battery always uses BatteryLevel below threshold. Dwell time applies to an open vehicle and geofences; age and interval filter old or discontinuous observations.</p><button class="button button-secondary">Save condition</button></form></details>'
    advanced += '</section>'
    body += '<details class="advanced-settings"><summary>Advanced settings · fields, timing and conditions</summary>'+advanced+'</details>'
    return body
