"""One local overview of acquisition, cost and event delivery; never polls Tesla."""
from html import escape
import math

from .collection_ui import STATES, money
from .profiles import estimate
from .ui import icon, local_time
from .ui_time import age_label, expiry_attributes
from .sample_evidence import DEFAULT_MAX_AGE_SECONDS


def render(collection, triggers, base, *, first=True):
    ref, name = collection["vehicle_ref"], collection["name"]
    remote = collection["remote"].get("data", {})
    verified = triggers["collection"]["verified"]
    applied = remote.get("config") if verified else None
    fields = (applied or {}).get("fields", {})
    selected = [i for i in triggers["items"] if i["enabled"] and not i["id"].startswith("rule:")]
    main = sum(i["id"].startswith("event:") for i in selected)
    state = {"active": 'Active', "paused": 'Paused', "unverified": 'Needs verification'}.get(collection["state"], STATES[collection["state"]])
    body = '<section class="console-overview" aria-label="Collection, cost and notifications">'
    suffix = '' if first else '-'+ref
    body += '<article id="raccolta'+suffix+'"><a class="overview-link" href="'+base+'/owner/collection/'+ref+'"><span>Data collection</span> →</a><h2>'+escape(state)+'</h2><p>'
    body += (str(len(fields))+' fields in the verified profile.' if verified else 'A saved profile does not prove collection is applied.')
    body += '</p></article>'
    body += '<article><a class="overview-link" href="'+base+'/owner/collection/'+ref+'#costo"><span>Streaming estimate</span> →</a><h2>'
    body += money(estimate(fields, collection["hours"])["estimated_gross_usd"])+' <span>USD</span>' if verified else 'Needs verification'
    body += '</h2><p>30 days · '+format(collection["hours"], 'g')+' hours/day. Other costs excluded.</p></article>'
    delivery = triggers["delivery_connection"]
    state_label = {"not_connected": 'Connection required', "partial": 'Partial connection', "selected_only": 'Connected · extend coverage', "shared": 'Connected'}[delivery["state"]]
    body += '<article id="eventi'+suffix+'"><a class="overview-link" href="'+base+'/owner/triggers/'+ref+'" aria-label="Manage events · '+escape(name, quote=True)+'"><span>Events for ChatGPT</span> →</a><h2>'+state_label+'</h2><p>'+str(main)+' events and '+str(len(selected)-main)+' changes selected.</p></article></section>'
    return body


def route_panel(evidence, timezone):
    """Draw only the permission-gated, bounded current geometry supplied to MCP."""
    observed = evidence.get('observation')
    if not observed:
        return ''
    available = evidence['status'] == 'available'
    age = observed.get('age_seconds')
    expires = DEFAULT_MAX_AGE_SECONDS-max(0, age) if available and age is not None else None
    body = '<details class="compact-panel route-panel"'+expiry_attributes(expires)+'><summary>'+icon('car')+'<span><strong>Received route</strong><small data-evidence-current>'+('Partial trace · telemetry source' if available else 'Current geometry unavailable')+'</small>'
    if available:
        body += '<small data-evidence-expired hidden>Current geometry unavailable</small>'
    body += '</span></summary><div class="disclosure-content"><p class="field-help">Assessment at page load, based on local samples.</p>'
    if available:
        points = evidence['geometry']['points']
        # Local equirectangular sketch, with longitude unwrapped at the date line.
        scale = max(0.01, math.cos(math.radians(sum(p['latitude'] for p in points)/len(points))))
        coordinates, previous = [], points[0]['longitude']
        for point in points:
            longitude = previous+(point['longitude']-previous+180)%360-180
            coordinates.append((longitude*scale, -point['latitude']))
            previous = longitude
        left, right = min(p[0] for p in coordinates), max(p[0] for p in coordinates)
        top, bottom = min(p[1] for p in coordinates), max(p[1] for p in coordinates)
        ratio = min(560/max(right-left, 0.000001), 220/max(bottom-top, 0.000001))
        plotted = ' '.join(f'{300+(x-(left+right)/2)*ratio:.2f},{130+(y-(top+bottom)/2)*ratio:.2f}' for x, y in coordinates)
        body += '<div data-evidence-current><svg class="route-sketch" viewBox="0 0 600 260" role="img" aria-label="Partial received route geometry; does not establish stops or current position"><polyline points="'+plotted+'"/></svg></div>'
        body += '<p class="field-help">'+str(evidence['geometry']['point_count'])+' received points. Schematic drawing without an external map. It does not prove the complete route, stops, final destination or current position.</p>'
        body += '<p data-evidence-expired hidden>This sample is now historical: geometry is not presented as a current route. Reload to reassess local data.</p>'
    else:
        reason = evidence.get('reason')
        body += '<p class="field-help">'+('The sample is historical, future-dated or invalid: it is not presented as a current route.' if reason == 'ROUTE_NOT_CURRENT_VALID' else 'The received format cannot produce usable geometry within read limits.')+'</p>'
    body += '<p class="field-help">Source: Fleet Telemetry · observed '+escape(local_time(observed['source_timestamp'], timezone))+'. '
    if age is not None:
        body += age_label(age, DEFAULT_MAX_AGE_SECONDS, '' if observed['quality'] == 'valid' else 'Invalid value')
    body += '</p><details class="metric-evidence"><summary>Reception and quality</summary><p>Received: '+escape(local_time(observed['received_at'], timezone) if observed.get('received_at') is not None else 'timestamp unavailable')+'.</p>'
    quality = {'valid': 'valid', 'invalid': 'invalid value', 'enum_unknown': 'unrecognized value', 'time_conflict': 'conflicting data', 'unqualified': 'semantics require qualification'}.get(observed['quality'], 'unavailable')
    body += '<p>Quality: '+quality+'. Sample provenance: '+('recorded' if observed.get('provenance', {}).get('status') == 'recorded' else 'not recorded')+'.</p></details>'
    return body+'</div></details>'
