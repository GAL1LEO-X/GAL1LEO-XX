"""Acquisition editor and cost calculator, with a server-rendered fallback."""
from html import escape
import secrets

from .collection import DELETE, full_profile
from .profiles import estimate, profile_fields
from .telemetry import FIELD_MAP
from .collection_catalog import CATEGORIES, PRESETS, field_info, timing_text
from .ui import local_time
from .trigger_dependencies import collection_impact
from .trigger_ui import READINESS
from .field_capabilities import selectable, select_maximum, REASONS

STATES = {"unverified": 'Status needs verification', "active": 'Configuration applied',
          "paused": 'No collection configured', "syncing": 'Waiting for application',
          "starting": 'Activation required', "pausing": 'Pause requested',
          "mismatch": 'Configuration differs from the latest request',
          "review": 'Change awaiting confirmation', "sending": 'Sending', "unknown": 'Outcome uncertain: check status'}

TEMPORARY_STATES = {"prepared": 'Awaiting confirmation', "active": 'Temporary window · application needs verification',
    "start_unknown": 'Start uncertain · verification required', "restore_pending": 'Restoration pending',
    "restore_accepted": 'Restoration accepted · awaiting verification', "restore_unknown": 'Restoration uncertain · do not repeat',
    "restored_verified": 'Previous verified profile', "superseded": 'Later request or configuration · restoration paused',
    "blocked": 'Restoration blocked', "restore_rejected": 'Restoration rejected',
    "cancelled": 'Request cancelled', "expired": 'Confirmation expired', "start_rejected": 'Start rejected'}


def temporary_summary(item, timezone, *, review=False):
    if not item:
        return ''
    body = '<section class="temporary-collection" aria-label="Temporary collection"><h3>Temporary collection</h3>'
    body += '<p><strong>'+TEMPORARY_STATES.get(item['status'], 'Status needs verification')+'</strong></p>'
    duration = str(item['duration_seconds']//60)+' minutes' if item['duration_seconds'] % 60 == 0 else str(item['duration_seconds'])+' seconds'
    price = '&lt; 0.01' if 0 < item['estimated_gross_usd'] < 0.005 else money(item['estimated_gross_usd'])
    body += '<dl><div><dt>Duration from submission</dt><dd>'+duration+'</dd></div>'
    body += '<div><dt>Streaming during the window</dt><dd>'+price+' estimated USD</dd></div>'
    if item.get('expires_at'):
        body += '<div><dt>Expected deadline</dt><dd>'+escape(local_time(item['expires_at'], timezone))+'</dd></div>'
    body += '</dl>'
    baseline = item.get('baseline')
    body += '<p>Restoration planned in the request: '+('previous profile, with '+str(len(baseline['fields']))+' fields and Tesla alerts '+('included' if baseline.get('customer_alerts') else 'excluded') if baseline else 'streaming paused, as before the temporary window')+'.</p>'
    if review:
        body += '<p>Confirmation authorizes startup, verification reads and this restoration. A subsequent different configuration is preserved. An uncertain outcome requires verification.</p>'
        body += '<p>Up to '+str(item.get('max_verification_reads', 10))+' automatic configuration reads, at least '+str(item.get('verification_interval_seconds', 60))+' seconds. Required access checks still apply. API reads and configuration writes are excluded from streaming costs.</p>'
    elif item['status'] in ('cancelled', 'expired', 'start_rejected'):
        body += '<p>This request did not activate the temporary window.</p>'
    else:
        body += '<p>Restoration completes only after Tesla readback. The deadline may be exceeded if the service stops or verification fails.</p>'
    if item.get('last_error'):
        reasons = {'SCOPE_REQUIRED': 'Permessi needs verification.', 'AUTHORIZATION_CHANGED': 'The connection changed.',
                   'REVISION_CONFLICT': 'Configuration or events changed.',
                   'RESTORE_VERIFICATION_LIMIT_REACHED': 'Automatic verification limit reached.',
                   'VEHICLE_ACCESS_REVOKED': 'Vehicle access revoked: owner review is required.',
                   'AUTHORIZATION_REMOVED': 'Authorization removed: owner review is required.'}
        body += '<p>'+escape(reasons.get(item['last_error'], 'Verification is required before restoration can be considered complete.'))+'</p><details><summary>Verification details</summary><p>'+escape(item['last_error'])+'</p></details>'
    if baseline:
        body += '<details><summary>Exact profile to restore</summary><ul class="collection-review-fields">'
        for name, opts in sorted(baseline['fields'].items()):
            info = field_info(FIELD_MAP[name]) if name in FIELD_MAP else {'label': name, 'delta_unit': 'unit unqualified'}
            body += '<li>'+escape(info['label']+' ('+name+') · '+timing_text(opts, info['delta_unit']))
            if opts.get('include_fields'):
                body += ' Included fields: '+escape(', '.join(opts['include_fields']))+'.'
            body += '</li>'
        body += '</ul></details>'
    return body+'</section>'


def money(value):
    return f"{value:.2f}"


def impact_notice(impact, *, editable=False):
    issues = impact["issues"]
    main = sum(i["trigger_id"].startswith("event:") for i in issues)
    body = '<aside class="collection-notice"'+(' id="trigger-impact"' if editable else '')+'><h3>Event compatibility</h3><p class="impact-status">'
    body += (str(main)+' primary events and '+str(len(issues)-main)+' field changes to review.' if issues else 'Data and timing cover the selected events.')
    body += '</p><div class="impact-details"><details><summary>See missing requirements and reasons</summary><p>'+escape(impact["note"])+'</p>'
    if impact["issues"]:
        missing = sorted({f for issue in impact["issues"] for f in issue["missing_fields"]})
        if missing:
            body += '<p>Required fields not included: '+escape(', '.join(field_info(FIELD_MAP[f])["label"] for f in missing))+'.</p>'
        if any(i["customer_alerts_missing"] for i in impact["issues"]):
            body += '<p>Tesla alert events also require alert collection.</p>'
        body += '<ul>'
        for issue in impact["issues"]:
            text = READINESS[issue["reason"]]
            if issue["missing_fields"]:
                text += ': '+', '.join(field_info(FIELD_MAP[f])["label"] for f in issue["missing_fields"])
            if issue["customer_alerts_missing"]:
                text += ' · Tesla alerts excluded'
            body += '<li>'+escape(issue["label"])+': '+escape(text)+'</li>'
        body += '</ul>'
    else:
        body += '<p>No collection gaps detected for the current selection.</p>'
    return body+'</details></div></aside>'


def hidden(view, csrf, *, revision=None):
    return (f'<input type="hidden" name="csrf" value="{escape(csrf, quote=True)}">'
            f'<input type="hidden" name="revision" value="{escape(view["revision"] if revision is None else revision, quote=True)}">'
            f'<input type="hidden" name="request_id" value="collection-{secrets.token_hex(16)}">')


def selection_notice(selection):
    if not selection:
        return ''
    body = '<details class="collection-notice selection-review"><summary>Compatibility: '+str(len(selection['excluded']))+' excluded fields with reasons · '+str(len(selection['warnings']))+' requirements need verification</summary><p>The proposal does not guarantee that Tesla accepts or sends every field. Excluded fields are never applied.</p><ul>'
    for item in selection['excluded']+selection['warnings']:
        body += '<li>'+escape(item['field']+': '+'; '.join(REASONS.get(r, r) for r in item['reasons']))+'</li>'
    return body+'</ul></details>'


def field_row(spec, opts, selected, hours, evidence=None, timezone='Europe/Amsterdam', vehicle_context=None):
    name = spec["field"]
    info = field_info(spec, vehicle_context)
    label, unit, description = info["label"], info["delta_unit"], info["description"]
    cost = estimate({name: opts}, hours)
    body = '<article class="collection-field" data-field="'+name+'" data-delta-unit="'+escape(unit, quote=True)+'" data-category="'+escape(spec["category"], quote=True)+'">'
    body += '<div class="field-overview"><label class="field-selection"><input type="checkbox" name="field" value="'+name+'"'+(' checked' if selected else '')+(' disabled' if info['qualification']['blockers'] and not selected else '')+'><span>'+escape(label)+'</span></label></div>'
    if info['qualification']['blockers']:
        body += '<p class="field-help">'+escape('; '.join(REASONS[r] for r in info['qualification']['blockers']))+'.</p>'
    if info['known_unavailable']:
        body += '<p class="field-help">Tesla marks this field as broken. Remove it before applying the profile.</p>'
    if info['hardware_requirement'] != 'field-specific availability not guaranteed':
        body += '<p class="field-help">Hardware requirement: '+escape(info['hardware_requirement'])+'. Availability on this vehicle needs verification.</p>'
    price = '&lt; 0.01' if 0 < cost["estimated_gross_usd"] < 0.005 else money(cost["estimated_gross_usd"])
    body += '<div class="field-schedule"><p class="field-frequency">'+escape(timing_text(opts, unit))+'</p><p class="field-estimate"><output>'+price+'</output> estimated USD/month for this field</p></div>'
    body += '<details class="field-customize"><summary>Details and frequency<span class="sr-only"> · '+escape(label)+'</span></summary><p class="field-description">'+escape(description)+' <span class="field-code">'+name+'</span></p><div class="field-timing">'
    if info['notes']:
        body += '<p class="field-help">Source limitations: '+escape(' '.join(info['notes']))+'</p>'
    body += '<p class="field-help">Source: Fleet Telemetry · configurability is stated in the requirements. Firmware: '+escape(spec['minimum_firmware_field'])+'. Client: '+escape(spec['minimum_client_field'])+'.</p>'
    for prefix, key, title in (("interval", "interval_seconds", 'Minimum interval (s)'), ("resend", "resend_interval_seconds", 'Resend (s)')):
        body += f'<label>{title}<input class="{prefix}" aria-label="{title} · {name}" name="{prefix}_{name}" type="number" min="1" max="86400" step="1" value="{opts.get(key, "")}"></label>'
    if spec["documented_type"].lower() in ("real", "integer") or name == "Location":
        minimum = 1 if name == "SelfDrivingMilesSinceReset" else 0
        body += f'<label>Minimum change <small>({escape(unit or "field unit")})</small><input class="delta" aria-label="Minimum change · {name}" name="delta_{name}" type="number" min="{minimum}" max="1000000" step="any" value="{opts.get("minimum_delta", "")}"></label>'
    included = escape(", ".join(opts.get("include_fields", [])), quote=True)
    body += f'<label>Fields to include<input class="includes" aria-label="Fields to include · {name}" name="include_{name}" value="{included}" placeholder="e.g. BatteryLevel, Locked" maxlength="12000"></label>'
    body += '<p>Optional comma-separated identifiers. They will be sent with this field, increasing the estimated signals. No independent frequency is guaranteed.</p>'
    body += '</div><p class="field-help">Timing in seconds: 60 = 1 minute, 300 = 5 minutes, 3,600 = 1 hour. Leave resend empty for the Tesla default. The threshold filters small changes.</p>'
    if evidence:
        states = {'not_verified': 'configuration needs verification', 'readback_outdated': 'readback predates the request',
                  'sync_pending': 'synchronization unconfirmed', 'confirmed': 'present in the verified profile',
                  'missing_from_readback': 'requested but absent from readback', 'not_configured': 'not configured in the readback'}
        samples = {'valid': 'valid', 'invalid': 'invalid', 'enum_unknown': 'unrecognized value', 'unqualified': 'observed protobuf type; semantics unqualified',
                   'time_conflict': 'timestamp conflict', 'not_observed': 'no archived sample',
                   'permission_required': 'location permission required'}
        config, sample = evidence['configuration'], evidence['reception']
        body += '<p class="field-help field-evidence">Current evidence: '+states[config['status']]+'. Last sample: '+samples.get(sample['status'], 'unverified')
        if sample['source_at'] is not None:
            body += ' · '+escape(local_time(sample['source_at'], timezone))
            body += ' · age '+str(round(sample['age_seconds']))+' s'
        if config['matches_requested_options'] is False:
            body += ' · frequencies/options differ from the request'
        cadence = sample.get('observed_cadence', {})
        if cadence.get('median_interval_seconds') is not None:
            body += ' · observed median interval '+str(cadence['median_interval_seconds'])+' s across '+str(cadence['sample_count'])+' samples'
        body += '. The form selection is a proposal; it does not change these observations.</p>'
    body += '<a class="field-help" href="https://developer.tesla.com/docs/fleet-api/fleet-telemetry/available-data" target="_blank" rel="noopener noreferrer">Tesla data definitions</a></details></article>'
    return body


def render(view, csrf, base, settings, *, fields=None, alerts=None, hours=None, preset="saved", proposal=None, trigger_revision=None, trigger_items=(), duration_seconds=None, draft_revision=None, revision_conflict=False):
    saved = view["saved"] or {}
    defaults = full_profile()
    fields = fields if fields is not None else saved.get("fields") or profile_fields("recommended")
    alerts = alerts if alerts is not None else "customer" in saved.get("alert_types", [] if saved else ["customer"])
    hours = hours if hours is not None else view["hours"]
    cost, continuous = estimate(fields, hours), estimate(fields, 24)
    path = base+"/owner/collection/"+view["vehicle_ref"]
    disabled = " disabled" if view["blocked"] else ""
    body = temporary_summary(view.get('temporary_collection'), settings.timezone)
    body += '<details class="collection-status"><summary><span>Current collection</span><strong>'+STATES[view["state"]]+'</strong><span class="status-control">Manage</span></summary><div class="collection-state-body"><div class="state-evidence">'
    if view["remote"]:
        body += '<p>Tesla evidence: '+escape(local_time(view["remote"]["at"], settings.timezone))+'. Does not update automatically.</p>'
    else:
        body += '<p>Check with Tesla to establish whether the profile is applied.</p>'
    evidence = view.get("evidence", {})
    field_evidence = view.get('field_evidence', {})
    if field_evidence:
        summary = field_evidence['summary']
        body += '<p>'+str(summary['saved_count'])+' saved fields · '+str(summary['observed_count'])+" present in the latest Tesla readback. Reception and availability are shown in each field's details.</p>"
    if evidence.get("reason") == "provider_sync_pending":
        body += '<p>'+('The observed profile matches the requested profile. ' if evidence.get("configuration_matches_target") else '')+'Tesla has not confirmed synchronization with the vehicle in the latest readback.</p>'
    if evidence.get("consumer"):
        consumer = evidence["consumer"]
        body += '<p>Data receiver: '+('active' if consumer["active"] else 'paused' if consumer["state"] == 'paused' else 'state unverified')+'. '
        body += ('First valid samples received after the request.' if evidence["samples_since_request"]["first_valid_at"] else 'No valid sample observed after the request.')+'</p>'
    if view["last_sample"]:
        body += '<p>Latest sample: '+escape(local_time(view["last_sample"], settings.timezone))+'.</p>'
    if view["remote"].get("data", {}).get("limit_reached"):
        body += '<p>Tesla reports that the telemetry application limit has been reached.</p>'
    if view["last"]:
        body += '<a href="'+base+'/owner/intents/'+view["last"]["id"]+'">Review the latest request</a>'
    body += '</div><div class="collection-state-actions"><form method="post" action="'+path+'">'+hidden(view, csrf)+'<button class="button button-secondary" name="collection_action" value="refresh">Check Tesla state</button><small>One API read, without waking the vehicle.</small></form>'
    if view["state"] == "paused" and saved:
        body += '<form method="post" action="'+path+'">'+hidden(view, csrf)+f'<button class="button button-secondary" name="collection_action" value="resume"{disabled}>Resume collection</button></form>'
    else:
        body += '<form method="post" action="'+path+'">'+hidden(view, csrf)+f'<button class="button button-quiet" name="collection_action" value="pause"{disabled}>Pause collection</button></form>'
    body += '</div></div></details>'

    body += '<details class="profile-picker preset-section"'+(' open' if not saved and preset == 'saved' else '')+'><summary><span>Choose a starting preset</span><small>Recommended, on demand or custom</small></summary><p>This loads a proposal only. Adjust and confirm it here or in ChatGPT.</p><div class="preset-grid">'
    recommended_cost = estimate(profile_fields("recommended"), hours)["estimated_gross_usd"]
    body += '<article class="preset-card preset-recommended"><p class="eyebrow">Recommended</p><h3>Essential automatic collection</h3><p>Battery, charging, charge limit, doors, gear, occupancy and software version for recommended events. Includes Tesla alerts.</p><strong>'+money(recommended_cost)+' USD/month stimati*</strong><a class="button button-primary" href="'+path+'?preset=recommended#proposta">Review data and cost</a></article>'
    body += '<article class="preset-card"><h3>Custom</h3><p>Choose the fields you need. Each field shows its interval, resend and cost contribution.</p><a class="button button-secondary" href="#proposta">Choose data and timing</a></article>'
    body += '<article class="preset-card"><h3>On demand</h3><p>No streaming. You can read data in chat; no new alerts based on continuous collection.</p><strong>USD 0.00 for streaming</strong><form method="post" action="'+path+'">'+hidden(view, csrf)+f'<button class="button button-secondary" name="collection_action" value="pause"{disabled}>Review pause</button></form></article></div>'
    body += '<p class="field-help">* '+format(hours, 'g')+' assumed hours/day. Other API calls and Tesla alerts are excluded. This is not a spending cap.</p><form method="get" class="collection-presets" action="'+path+'#proposta"><label>Other presets<select name="preset" required>'
    if preset not in PRESETS:
        body += '<option value="" disabled selected>Custom</option>'
    body += ''.join('<option value="'+key+'"'+(' selected' if key == preset else '')+'>'+label+'</option>' for key, label in PRESETS.items())
    body += '</select></label><button class="button button-secondary">Load into form</button></form></details>'

    current = PRESETS.get(preset, 'Custom')
    if preset == "saved":
        current = 'Last saved profile' if saved else PRESETS["recommended"]
    body += '<section class="collection-editor" id="proposta"><div class="section-heading"><div><h2>Fields and frequencies</h2><p class="proposal-label"><strong id="proposal-name">'+current+'</strong> · Changes awaiting confirmation</p></div></div>'
    if revision_conflict:
        body += '<aside class="collection-notice" role="alert"><h3>Collection changed while you edited the draft</h3><p>Entered values are retained for comparison. This estimate remains bound to the original revision and cannot be applied.</p><a href="'+path+'#proposta">Reload current profile</a></aside>'
    if preset == 'full':
        selection = select_maximum(defaults, view.get('vehicle_context'))[1]
        body += selection_notice(selection)
    if proposal:
        body += '<aside class="collection-notice" id="trigger-proposal"><h3>Collection for selected events</h3>'
        if proposal["available"]:
            body += '<p>Previous estimate: '+money(proposal["previous_estimate"]["estimated_gross_usd"])+' USD/month. Proposed: <strong>'+money(proposal["estimate"]["estimated_gross_usd"])+' USD/month</strong>, with the same assumed hours.</p>'
            body += '<details><summary>See '+str(len(proposal["changed_fields"]))+' proposed changes</summary><p>'+escape(proposal["note"])+'</p><ul>'
            for name, change in proposal["changed_fields"].items():
                info = field_info(FIELD_MAP[name])
                body += '<li>'+escape(info["label"])+(' · added' if change["before"] is None else ' · timing changed')+': '+escape(timing_text(change["after"], info["delta_unit"]))+'</li>'
            body += '</ul></details>'
            if proposal["unresolved"]:
                body += '<p>'+str(len(proposal["unresolved"]))+' events also require permissions or rules: collection alone does not activate them.</p>'
        else:
            body += '<p>'+escape(proposal["reason"])+'</p><p>The form remains a separate proposal, without event-specific adjustments.</p>'
        body += '</aside>'

    disabled = " disabled" if view['blocked'] or revision_conflict else ""
    body += '<form method="post" action="'+path+'#proposta" id="collection-editor" data-locked="'+str(view["blocked"] or revision_conflict).lower()+'">'+hidden(view, csrf, revision=draft_revision)
    if trigger_revision is not None:
        body += '<input type="hidden" name="trigger_revision" value="'+str(trigger_revision)+'">'
    body += '<div class="collection-live-cost"><span><output id="selected-count">'+str(len(fields))+'</output> selected fields</span><a href="#costo"><strong><output id="editing-cost">'+money(cost["estimated_gross_usd"])+'</output> USD/month</strong> · see estimate</a></div>'
    body += '<div class="collection-workspace"><div class="collection-choices"><section class="collection-selected"><h3 class="sr-only">Selected fields and frequencies</h3><p class="field-help collection-guidance">Sent while the vehicle is awake and connected, if the field is available. Requested timing does not guarantee an exact cadence. Open a field to adjust timing and threshold.</p>'
    body += '<details class="collection-tempo" hidden><summary>Adjust all frequencies together</summary><div class="button-row"><button type="button" class="button button-secondary" data-tempo="2">Less frequent · intervals ×2</button><button type="button" class="button button-secondary" data-tempo="0.5">More frequent · intervals ÷2</button><button type="button" class="button button-quiet" data-tempo="reset">Restore loaded timing</button></div><p id="tempo-status" class="field-help" role="status">Change intervals and resends for selected fields. Thresholds remain unchanged.</p></details>'
    specs = {category: sorted((row for row in FIELD_MAP.values() if row['catalog_status'] in ('DOCUMENTED', 'PROTO_ONLY_UNDOCUMENTED') and row["category"] == category), key=lambda r: r["field"]) for category in CATEGORIES}
    body += '<label class="selected-search" hidden>Search selected fields<input type="search" id="selected-search" placeholder="Field name or description"></label><p id="selected-search-status" class="field-help" role="status"></p>'
    body += '<div id="selected-fields" tabindex="0" role="region" aria-label="Selected fields and frequencies">'
    for rows in specs.values():
        for spec in rows:
            if spec["field"] in fields:
                body += field_row(spec, fields[spec["field"]], True, hours, field_evidence.get('fields', {}).get(spec['field']), settings.timezone, view.get('vehicle_context'))
    body += '</div><p id="no-selected-fields" class="field-help"'+(' hidden' if fields else '')+'>No fields selected. Add fields from the catalogue; use Pause collection to stop collection.</p></section>'
    body += '<div class="collection-alert-block"><label class="collection-alerts"><input name="customer_alerts" type="checkbox"'+(' checked' if alerts else '')+'> Include Tesla driver alerts</label><p class="field-help">Sent when an alert occurs. Their cost is excluded from the estimate.</p></div>'
    body += '<details class="collection-catalog"><summary>Add or choose more fields <span>'+str(sum(len(rows) for rows in specs.values()))+' declared fields · '+str(len(defaults))+' configurable in the plugin</span></summary><p class="field-help">Compatibility, reception and quality are shown for each field. Protocol-only fields require semantic qualification. Select all includes only locally eligible fields and does not guarantee reception. Selected fields move to the list above.</p><label class="collection-search" hidden>Search fields<input type="search" id="field-search" placeholder="Battery, temperature, GPS…"></label>'
    body += '<div class="collection-bulk" hidden><button type="button" class="button button-secondary" data-select="all">Select all</button><button type="button" class="button button-secondary" data-select="none">Deselect all</button></div><noscript><p>Use Calculate estimate to update the review after selection.</p></noscript><p id="catalog-search-status" class="field-help" role="status"></p>'
    for category, rows in specs.items():
        body += '<details class="collection-category" data-category="'+escape(category, quote=True)+'"><summary>'+CATEGORIES[category]+'<span>'+str(sum(r["field"] in fields for r in rows))+' / '+str(len(rows))+' selected</span></summary><div class="category-fields">'
        for spec in rows:
            if spec["field"] not in fields:
                body += field_row(spec, defaults.get(spec["field"], {"interval_seconds": 60}), False, hours, field_evidence.get('fields', {}).get(spec['field']), settings.timezone, view.get('vehicle_context'))
        body += '</div></details>'
    body += '</details></div><aside class="collection-decision">'
    body += '<section class="cost-calculator" id="costo" aria-label="Monthly cost calculator"><div><p class="eyebrow">Your proposal · 30 days</p><p class="cost-value"><output id="monthly-cost">'+money(cost["estimated_gross_usd"])+'</output> <span>USD / month</span></p><p>Conservative streaming-only estimate</p></div>'
    body += f'<label>Hours per day with an awake vehicle<input id="active-hours" name="hours" type="number" min="0.1" max="24" step="0.1" value="{hours:g}" required></label>'
    body += '<details class="cost-method"><summary>Assumptions and excluded costs</summary><p><output id="signal-count">'+str(cost["planned_signals_30_days"])+'</output> estimated signals. Changes at every interval, plus resends.</p><p>With an awake vehicle for 24 hours: <output id="continuous-cost">'+money(continuous["estimated_gross_usd"])+'</output> USD/month. These hours do not schedule data collection.</p><p>Excludes other API calls, Tesla alerts, retransmissions, hosting, taxes and the Tesla discount. This is not a spending cap.</p><p>Rate: USD 1 / 150,000 signals. <a href="https://developer.tesla.com/docs/fleet-api/billing-and-limits" target="_blank" rel="noopener noreferrer">Tesla pricing</a>.</p></details>'
    body += '<p id="calculator-status" class="field-help" aria-live="polite">Local estimate. Collection changes only after confirmation.</p></section>'
    body += '<section class="collection-duration"><label for="collection-duration">Collection duration</label><select name="duration_seconds" id="collection-duration">'
    durations = {None: 'Continue until the next change', 900: '15 minutes', 3600: '1 hour', 14400: '4 hours', 86400: '24 hours'}
    if duration_seconds is not None and duration_seconds not in durations:
        durations[duration_seconds] = str(duration_seconds)+' seconds'
    body += ''.join('<option value="'+(str(value) if value is not None else '')+'"'+(' selected' if value == duration_seconds else '')+'>'+label+'</option>' for value, label in durations.items())
    body += '</select><p id="temporary-estimate" class="field-help" aria-live="polite">The review will validate the temporary duration and cost.</p><p class="field-help">A temporary window restores the previous verified profile or pause state. Review duration, cost and restoration before confirmation.</p></section>'
    body += impact_notice(collection_impact(trigger_items, fields, alerts), editable=True)
    body += '<div class="collection-submit"><button class="button button-primary" name="collection_action" value="configure"'+disabled+'>Review configuration</button><button class="button button-secondary" name="collection_action" value="estimate">Calculate estimate</button></div><p class="decision-note">Review data, timing and cost first. Then confirm here or in chat. No automatic wake command.</p></aside></div></form></section>'

    body += '<details class="collection-help"><summary>How delivery, timing and costs work</summary><p><strong>Minimum interval:</strong> limits submissions of changed values. <strong>Resend:</strong> also requests an unchanged value, if available; it does not guarantee a sample at exact intervals. <strong>Threshold:</strong> ignores changes below the threshold.</p><p>Parked does not mean asleep. New data and alerts are not guaranteed while the vehicle is asleep or disconnected. Calculator hours are an assumption, not a schedule.</p><p>Slower collection may make data too old for rules. Field frequency is separate from ChatGPT event batching. History retained for '+str(settings.history_days)+' days.</p></details>'
    body += '<details class="collection-maintenance"><summary>Pause, resume and spending limit</summary><section class="collection-controls"><div><h2>Pause and resume</h2><p>Pausing removes this app\'s Tesla streaming configuration. The profile and history are retained. Confirmation and Tesla readback are required; data already in transit may still arrive.</p></div><div class="button-row">'
    body += '<form method="post" action="'+path+'">'+hidden(view, csrf)+f'<button class="button button-secondary" name="collection_action" value="pause"{disabled}>Pause collection</button></form>'
    resume_disabled = disabled or (" disabled" if not saved or view["state"] == "active" else "")
    body += '<form method="post" action="'+path+'">'+hidden(view, csrf)+f'<button class="button button-secondary" name="collection_action" value="resume"{resume_disabled}>Resume saved profile</button></form></div></section><aside class="collection-billing"><h2>Billing limit</h2><p>Set the overall limit in the <a href="https://developer.tesla.com/" target="_blank" rel="noopener noreferrer">Tesla Developer portal</a>. The local limit applies to API requests, not streaming. A Tesla block may remove profiles; resumption is not automatic.</p></aside></details>'
    return body


def review(item, store, settings, *, temporary=None):
    if item.get('review_complete') is False:
        return '<p class="collection-notice" role="status">Review unavailable: preparation is incomplete. No estimate or authorization is inferred. Cancel this request and prepare a new one.</p>'
    from .triggers import Triggers
    config = item["arguments"].get("config", {})
    impact = impact_notice(collection_impact(Triggers(store).view(item["vehicle"], settings.allowed_scopes)["items"],
                                           config.get("fields", {}), "customer" in config.get("alert_types", [])))
    if item["operation"] == DELETE:
        return '<p class="collection-notice">Pause this app\'s streaming. The chosen profile stays saved for resumption. History remains available until retention expires. Verify actual suspension with Tesla; this does not stop other apps.</p>'+impact
    config = item["arguments"]["config"]
    fields = config["fields"]
    import json
    with store.db() as db:
        row = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section=?", (item["vehicle"], "telemetry_preview_"+item["id"])).fetchone()
    preview = json.loads(row[0]) if row else {}
    hours = preview.get("hours") if preview.get("intent_id") == item["id"] else None
    cost = estimate(fields, hours) if hours is not None else None
    body = temporary_summary(temporary, settings.timezone, review=True)
    body += '<dl class="parameters"><div><dt>Selected fields</dt><dd>'+str(len(fields))+'</dd></div><div><dt>'+('Comparison if continued for 30 days' if temporary else 'Gross estimate over 30 days')+'</dt><dd>'+(money(cost["estimated_gross_usd"])+' USD' if cost else 'Unavailable for this request')+'</dd></div><div><dt>Assumed awake time</dt><dd>'+(format(hours, 'g').replace('.', ',')+' hours/day' if hours is not None else 'Not recorded for this request')+'</dd></div><div><dt>Tesla alerts</dt><dd>'+('Included' if config.get("alert_types") else 'Excluded')+'</dd></div></dl>'
    body += selection_notice(preview.get('selection_review'))
    body += '<p class="muted">Conservative estimate, not a spending cap. Excludes other calls, alerts, retransmissions, taxes and the Tesla discount. No automatic wake commands.</p><details class="result-details"'+(' open' if len(fields) <= 12 else '')+'><summary>Fields and intervals to apply</summary><ul class="collection-review-fields">'
    for name, opts in sorted(fields.items()):
        info = field_info(FIELD_MAP[name])
        text = info["label"]+' ('+name+') · '+timing_text(opts, info["delta_unit"])
        if opts.get('include_fields'):
            text += ' Included fields: '+', '.join(opts['include_fields'])+'.'
        body += '<li>'+escape(text)+'</li>'
    return body+'</ul></details>'+impact
