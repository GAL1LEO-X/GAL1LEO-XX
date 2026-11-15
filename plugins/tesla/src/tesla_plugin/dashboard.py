"""Owner-only vehicle overview. Every value retains its observation time."""
from html import escape
import json
import math

from .ui import icon, local_time
from .trigger_catalog import EVENT_LABELS
from .gear_evidence import view as gear_evidence
from .operating_context import explain
from .sample_evidence import DEFAULT_MAX_AGE_SECONDS, view as sample_view, history_provenance
from .ui_time import age_label, expiry_attributes

CARDS = {"Locked": ('Locks', "", "lock"), "InsideTemp": ('Cabin', "°C", "climate"),
         "OutsideTemp": ('Outside', "°C", "outside"), "Version": ("Software", "", "software")}
CHARGE_STATES = {"Charging": 'Charging', "Complete": 'Charging completed', "Stopped": 'Charging interrupted',
                 "Disconnected": 'Cable disconnected', "Starting": 'Charging started', "NoPower": 'No power'}
QUALITY_LABELS = {"invalid": 'Invalid value', "enum_unknown": 'Unrecognized value',
                  "time_conflict": 'Conflicting data', "unqualified": 'Semantics require qualification'}


def scalar_evidence(evidence):
    """Fixed scalar cards never serialize legacy structures, at either time.

    Stored quality is not a type or privacy grant. Preserve it and the source
    metadata, but withhold values that cannot belong to this card, regardless
    of the current location permission. Do not mutate the shared evidence.
    """
    field = evidence['field']
    result = dict(evidence)
    for key in ('current_observation', 'last_valid_observation'):
        item = evidence[key]
        if not item or item['value'] is None:
            continue
        value = item['value']
        if field in ('BatteryLevel', 'InsideTemp', 'OutsideTemp'):
            usable = type(value) in (int, float) and math.isfinite(value)
            if field == 'BatteryLevel':
                usable = usable and 0 <= value <= 100
        elif field == 'Locked':
            usable = type(value) is bool
        else:
            usable = type(value) is str
        if not usable:
            result[key] = item | {'value': None, 'display_value_withheld': True}
    return result


def observation(record, now, timezone):
    if not record:
        return '<span class="observation">Waiting for data</span>'
    age = record["age_seconds"]
    if age is not None and -0.001 <= age < 0:
        age = 0
    source = 'Telemetry' if record['provenance'].get('source') == 'fleet_telemetry' else 'Source not recorded'
    quality_label = 'Unusable format' if record.get('display_value_withheld') else QUALITY_LABELS.get(record['quality'], '')
    label = quality_label
    if not label:
        label = {'fresh': 'Recent', 'stale': 'Historical', 'future': 'Future timestamp'}.get(record['freshness'], 'Unknown age')
    if age is not None and age >= 0:
        label += ' · '+(f'{int(age)} s ago' if age < 60 else f'{int(age)//60} min ago' if age < 3600 else f'{int(age)//3600} h ago')
    elif age is not None and record['quality'] != 'valid':
        label += ' · future timestamp'
    attributes = (' data-sample-age="'+str(age)+'" data-age-limit="'+str(DEFAULT_MAX_AGE_SECONDS)+'" data-quality-label="'+escape(quality_label, quote=True)+'"') if age is not None and age >= 0 else ''
    return '<span class="observation'+(' is-stale' if record['status'] != 'valid' or record.get('display_value_withheld') else '')+'"'+attributes+'><span class="observation-label">'+escape(label)+'</span><span class="observation-source">'+escape(source)+'</span></span>'


def value_of(record):
    return record['value'] if record and record['quality'] == 'valid' and record['freshness'] != 'future' else None


def evidence_detail(evidence, timezone, *, label, unit=''):
    evidence = scalar_evidence(evidence)
    body = '<details class="metric-evidence"><summary>Source and history<span class="sr-only"> · '+escape(label)+'</span></summary>'
    for key, title in (('current_observation', 'Latest observation'), ('last_valid_observation', 'Last valid value · historical')):
        item = evidence[key]
        if not item:
            body += '<p>'+title+': no recorded data.</p>'
            continue
        if key == 'last_valid_observation' and evidence['current_observation'] and item['source_timestamp'] == evidence['current_observation']['source_timestamp']:
            continue
        value = item['value']
        if type(value) is bool:
            value = 'Yes' if value else 'No'
        missing = 'Format cannot be displayed in this card' if item.get('display_value_withheld') else QUALITY_LABELS.get(item['quality'], 'Unavailable')
        body += '<p><strong>'+title+'</strong>: '+escape(str(value) if value is not None else missing)+((' '+escape(unit)) if value is not None and unit else '')+'</p>'
        at = item['source_timestamp']
        body += '<p>Observed: '+escape(local_time(at, timezone) if at is not None else 'timestamp unavailable')
        if item['received_at'] is not None:
            body += ' · Received: '+escape(local_time(item['received_at'], timezone))
        body += '</p>'
        provenance = item['provenance']
        body += '<p>Source: '+('Fleet Telemetry' if provenance.get('source') == 'fleet_telemetry' else 'not recorded for this sample')
        body += '. Quality: '+escape('valid' if item['quality'] == 'valid' else QUALITY_LABELS.get(item['quality'], 'unavailable').lower())+'.</p>'
        if provenance['status'] == 'recorded':
            body += '<details><summary>Sample diagnostics</summary><p>'
            body += escape(' · '.join(str(provenance[key]) for key in ('source_transport', 'quality_reason', 'oneof_branch', 'decoder_version', 'contract_version') if provenance.get(key)))
            body += '</p></details>'
    return body+'<p>Historical values do not prove current state. This view reads local data only.</p></details>'


def chart_paths(rows):
    """Keep every validity boundary before reducing a continuous segment."""
    paths, segment, previous = [], [], None
    for row in rows:
        value = json.loads(row["value"]) if row["value"] is not None else None
        if row["quality"] != "valid" or type(value) not in (int, float) or not 0 <= value <= 100:
            if segment:
                paths.append(segment)
            segment, previous = [], None
            continue
        if previous is not None and row["source_at"]-previous > 300:
            paths.append(segment)
            segment = []
        segment.append((row["source_at"], value))
        previous = row["source_at"]
    if segment:
        paths.append(segment)
    return paths


def reduce_path(path, start, bucket_seconds=12):
    """First/last/min/max per time bucket, never across an invalid-data gap.

    Aggregates are calculated separately from the complete observations. Dense
    paths are reduced for display only; even a one-sample spike is retained.
    """
    buckets = {}
    for index, (at, value) in enumerate(path):
        bucket = int((at-start)//bucket_seconds)
        buckets.setdefault(bucket, []).append((index, at, value))
    selected = set()
    for rows in buckets.values():
        selected.update(row[0] for row in (rows[0], rows[-1], min(rows, key=lambda r: r[2]), max(rows, key=lambda r: r[2])))
    return [path[index] for index in sorted(selected)]


def chart(rows, now):
    """One-hour view; retain endpoints/extrema, 0–100 scale and quality gaps."""
    paths = [reduce_path(path, now-3600) for path in chart_paths(rows)]
    if not paths:
        return '<div class="empty-chart">'+icon("battery")+'<p>History begins with the first sample.</p><span>No valid observations in the last hour.</span></div>'
    def drawing(width, layout):
        right = width-18
        segments = [[f"{42+(right-42)*(at-(now-3600))/3600:.2f},{180-1.5*value:.2f}" for at, value in path] for path in paths]
        lines = ''.join('<polyline class="chart-line" points="'+' '.join(p)+'"/>' for p in segments)
        points = ''.join(f'<circle class="chart-point" cx="{v.split(",")[0]}" cy="{v.split(",")[1]}" r="2.5"/>' for p in segments for v in p)
        return (f'<svg class="battery-chart battery-chart-{layout}" viewBox="0 0 {width} 224" role="img" '
            'aria-label="Battery observations over the last hour, scale 0 to 100 percent">'
            f'<path class="chart-grid" d="M42 30H{right}M42 105H{right}M42 180H{right}"/>'
            '<g class="chart-labels"><text x="0" y="34">100%</text><text x="8" y="109">50%</text><text x="15" y="184">0%</text>'
            f'<text x="42" y="215">−60 min</text><text x="{(42+right)/2:g}" y="215" text-anchor="middle">−30 min</text>'
            f'<text x="{right}" y="215" text-anchor="end">Now</text></g>'+lines+points+'</svg>')
    return '<div class="chart-view">'+drawing(780, "desktop")+drawing(360, "mobile")+'</div>'


def render(store, ref, timezone, *, name, state, base, primary=True):
    now = store.clock()
    evidence = {field: scalar_evidence(sample_view(store, ref, field)) for field in ('BatteryLevel', 'DetailedChargeState', *CARDS)}
    latest = {field: item['current_observation'] for field, item in evidence.items()}
    battery = value_of(latest.get("BatteryLevel"))
    if type(battery) not in (int, float) or not 0 <= battery <= 100:
        battery = None
    charge = value_of(latest.get("DetailedChargeState"))
    charge_text = CHARGE_STATES.get(str(charge).removeprefix("DetailedChargeState"), 'Charging state unavailable')
    vehicle_state = {"online": "Online", "asleep": 'Asleep', "offline": "Offline"}.get(state, 'Unavailable')
    listed_age = max(0, int(now-store.vehicle(ref)['checked']))
    listed_age_text = f'{listed_age} s ago' if listed_age < 60 else f'{listed_age//60} min ago' if listed_age < 3600 else f'{listed_age//3600} h ago'
    heading = "h1" if primary else "h2"
    body = f'<section class="vehicle-panel" aria-label="{escape(name, quote=True)}"><div class="vehicle-heading"><{heading}>{escape(name)}</{heading}><span class="vehicle-state">Tesla vehicle list: {vehicle_state} · read {listed_age_text}</span></div>'
    body += '<div class="vehicle-overview"><figure class="vehicle-visual">'
    body += f'<img src="{base}/assets/model-y-legacy.png?v=b26ae3522df8" width="1536" height="1024" alt="Illustration of a black Model Y Legacy Performance" fetchpriority="high"></figure>'
    body += '<div class="charge-summary"><p class="eyebrow">State of charge</p>'
    body += '<p class="charge-value">'+(f'{battery:g}<span>%</span>' if battery is not None else '<span class="unavailable">Unavailable</span>')+'</p>'
    if battery is not None:
        body += f'<meter class="battery-meter" min="0" max="100" value="{battery:g}" aria-label="Battery level">{battery:g}%</meter>'
    body += observation(latest.get("BatteryLevel"), now, timezone)
    body += evidence_detail(evidence['BatteryLevel'], timezone, label='Battery', unit='%')
    body += '<div class="charge-state">'+icon("bolt")+'<div><strong>'+escape(charge_text)+'</strong>'+observation(latest.get("DetailedChargeState"), now, timezone)+evidence_detail(evidence['DetailedChargeState'], timezone, label='Charging')+'</div></div>'
    body += '</div></div>'
    body += '<div class="vehicle-metrics">'
    for field, (label, unit, symbol) in CARDS.items():
        record, value = latest.get(field), value_of(latest.get(field))
        display = 'Unavailable' if value is None else str(value)
        if field == "Locked" and value is not None:
            display = 'Locked' if value else 'Unlocked'
        elif type(value) in (int, float):
            display = f"{value:g}".replace(".", ",")
        body += f'<article class="vehicle-metric">{icon(symbol)}<h3>{escape(label)}</h3><p class="metric-value">{escape(display)}'+(f' <span class="unit">{unit}</span>' if value is not None else '')+'</p>'+observation(record, now, timezone)+evidence_detail(evidence[field], timezone, label=label, unit=unit)+'</article>'
    return body+'</div>'+park_panel(store, ref, timezone)+'</section>'


def park_panel(store, ref, timezone):
    evidence = gear_evidence(store, ref)
    label = {"verified": 'Park observed', "conflicting": 'Conflicting sources', "not_park": 'Gear other than Park',
             "stale": 'Observation expired', "unknown": 'Park cannot be verified'}[evidence["status"]]
    # Invalidate the displayed assessment at its first evidence deadline. A
    # later REST observation may still be usable; only the backend can qualify
    # a new command. The browser does not relabel an expired assessment as P.
    remaining = [row['max_age_seconds']-row['age_seconds'] for row in evidence['observations'] if row['usable']]
    diagnostic = explain(store, ref, evidence)
    remaining.extend(30-row['age_seconds'] for row in diagnostic['observations'].values()
                     if row['quality'] == 'valid' and row['recent_for_diagnosis'])
    expires = min(remaining) if remaining else 30
    body = '<details class="compact-panel park-panel"'+expiry_attributes(expires)+'><summary>'+icon("car")+'<span><strong>Gear and Park</strong><small data-evidence-current>'+label+'</small><small data-evidence-expired hidden>Assessment expired</small></span></summary><div class="disclosure-content">'
    body += '<p class="field-help">Assessment at page load, based on local samples.</p>'
    body += '<p class="operating-context" data-evidence-current>'+escape(diagnostic['message'])+'</p>'
    body += '<p data-evidence-expired hidden>The displayed assessment expired. Samples below are historical; reload to reassess local data. Each command independently checks its prerequisites.</p>'
    for observation in evidence["observations"]:
        source = 'Telemetry' if observation["source"] == "fleet_telemetry" else 'API read'
        at = local_time(observation["source_timestamp"], timezone) if observation["source_timestamp"] is not None else 'timestamp unavailable'
        body += '<p>'+source+': <strong>'+escape(observation["value"] or 'data unavailable')+'</strong> · '+escape(at)
        if observation["source_timestamp"] is None:
            body += ' · no usable sample'
        elif observation["quality"] != "valid":
            body += ' · invalid value'
        body += ' · '+age_label(observation['age_seconds'], observation['max_age_seconds'], '' if observation['quality'] == 'valid' else 'Data unavailable')+'</p>'
    last = evidence["last_valid_observation"]
    if last:
        body += '<p>Latest valid telemetry value: <strong>'+escape(last["value"])+'</strong> · '+escape(local_time(last["source_timestamp"], timezone))+'. This is historical data.</p>'
    current = evidence["current_telemetry"] or {}
    if current.get("input_evidence", {}).get("normalization_reason") == "invalid_branch_received":
        body += '<p>The latest received record contains the invalid-value marker. The cause on the vehicle is undetermined.</p>'
    body += '<details class="operating-signals"><summary>Driving-context signals</summary><dl>'
    labels = {'Gear': 'Gear', 'DriveRail': 'Drive system power', 'BrakePedal': 'Brake pedal',
              'DriverSeatOccupied': 'Driver occupancy', 'CenterDisplay': 'Centre display',
              'DetailedChargeState': 'Charging', 'ChargingCableType': 'Charging cable', 'Locked': 'Locks'}
    qualities = {'missing': 'No samples', 'invalid': 'Data unavailable',
                 'enum_unknown': 'Unrecognized value', 'time_conflict': 'Timestamp conflict',
                 'unqualified': 'Semantics require qualification'}
    for name, observation in diagnostic['observations'].items():
        value = observation['value']
        text = qualities.get(observation['quality'], 'Unusable data')
        if isinstance(value, (dict, list)):
            text = 'Unusable format'
        elif observation['quality'] == 'valid':
            if name == 'DriveRail':
                text = 'Active' if value else 'Inactive'
            elif name == 'Locked':
                text = 'Locked' if value else 'Unlocked'
            elif name == 'BrakePedal':
                text = 'Pressed' if value else 'Released'
            elif name == 'DriverSeatOccupied':
                text = 'Detected' if value else 'Not detected'
            elif name == 'DetailedChargeState':
                text = CHARGE_STATES.get(str(value).removeprefix('DetailedChargeState'), str(value))
            else:
                text = str(value).removeprefix('ShiftState').removeprefix('DisplayState').removeprefix('CableType')
                text = {'Accessory': 'Accessories', 'On': 'On', 'Off': 'Off', 'Charging': 'Charging'}.get(text, text)
        timing = ' · '+age_label(observation['age_seconds'], 30, '' if observation['quality'] == 'valid' else 'Data unavailable') if observation['age_seconds'] is not None else ''
        body += '<div><dt>'+escape(labels.get(name, name))+'<small>'+escape(name)+'</small></dt><dd>'+escape(text)+timing+'</dd></div>'
    body += '</dl></details>'
    return body+'<p class="field-help">Historical data does not replace current Park evidence. Requirements depend on the command; this view sends no vehicle requests.</p></div></details>'


def history(store, ref, timezone):
    """Secondary information stays collapsed; expanding it makes no API call."""
    now = store.clock()
    with store.db() as db:
        rows = db.execute("SELECT * FROM samples WHERE vehicle=? AND field='BatteryLevel' AND source_at>=? AND source_at<=? ORDER BY source_at,id", (ref, now-3600, now)).fetchall()
        provenance = {}
        # Bound SQL parameters even when the hour contains dense/replayed data.
        for offset in range(0, len(rows), 500):
            provenance.update(history_provenance(db, [row['id'] for row in rows[offset:offset+500]]))
        rows = [dict(row) | ({'quality': 'time_conflict'} if provenance.get(row['id'], {}).get('timestamp_conflict') else {}) for row in rows]
        events = db.execute("SELECT name,occurred FROM events WHERE vehicle=? ORDER BY occurred DESC LIMIT 12", (ref,)).fetchall()
    valid = [json.loads(r["value"]) for r in rows if r["quality"] == "valid" and r["value"] is not None]
    valid = [v for v in valid if type(v) in (int, float) and 0 <= v <= 100]
    summary = (f'{min(valid):g}–{max(valid):g} %' if min(valid) != max(valid) else f'{valid[0]:g} %') if valid else 'No valid data'
    body = '<div class="vehicle-history"><details class="compact-panel history-panel" id="history-'+ref+'"><summary>'+icon("battery")+'<span><strong>Battery over time</strong><small>Last hour · '+escape(summary)+'</small></span></summary><div class="disclosure-content">'
    shown = sum(len(reduce_path(path, now-3600)) for path in chart_paths(rows))
    body += chart(rows, now)+'<p class="chart-note">'+str(len(rows))+' samples over the full hour · '+str(shown)+' displayed points. '
    body += 'Chart downsampling preserves the start, end and extremes of each segment; the summary uses all valid samples. Gaps indicate absent or invalid observations.</p></div></details>'
    body += '<details class="compact-panel events-panel"><summary>'+icon("clock")+'<span><strong>Observed events</strong><small>'
    body += (escape(EVENT_LABELS.get(events[0]["name"], events[0]["name"]))+' · '+escape(local_time(events[0]["occurred"], timezone))) if events else 'No recorded events'
    body += '</small></span></summary><div class="disclosure-content">'
    if events:
        body += '<p class="field-help">Last '+str(len(events))+' recorded events. This does not indicate delivery to ChatGPT.</p><ul class="event-list">'
        for event in events:
            label = EVENT_LABELS.get(event["name"], event["name"].replace("_", " ").capitalize())
            body += '<li>'+icon("clock")+'<span>'+escape(label)+'</span><time>'+escape(local_time(event["occurred"], timezone))+'</time></li>'
        body += '</ul>'
    else:
        body += '<p class="field-help">Events appear when their conditions are detected.</p>'
    return body+'</div></details></div>'
