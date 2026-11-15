"""Local evidence only. Observation, acceptance and causal proof stay distinct."""
from collections import Counter
import json

from .store import canonical
from .errors import TeslaError

EFFECT_SECTIONS = {"vehicle_wake_up": "vehicle_observation", "set_temps": "climate_state",
                   "auto_conditioning_start": "climate_state", "auto_conditioning_stop": "climate_state",
                   "set_charge_limit": "charge_state", "door_lock": "vehicle_state", "door_unlock": "vehicle_state"}
EFFECT_SECTIONS.update({
    "charge_start": "charge_state", "charge_stop": "charge_state", "set_charging_amps": "charge_state",
    "charge_port_door_open": "charge_state", "charge_port_door_close": "charge_state",
    "set_sentry_mode": "vehicle_state", "close_trunk": "vehicle_state",
    "remote_seat_heater_request": "climate_state", "set_seat_heaters": "climate_state",
    "remote_steering_wheel_heater_request": "climate_state",
    "remote_auto_steering_wheel_heat_climate_request": "climate_state",
    "remote_steering_wheel_heat_level_request": "climate_state",
})
SEAT_FIELDS = {0: "seat_heater_left", 1: "seat_heater_right", 2: "seat_heater_rear_left",
               4: "seat_heater_rear_center", 5: "seat_heater_rear_right"}


def consumer_heartbeat(store, state):
    """A local process heartbeat; it never polls Tesla or changes collection."""
    now = store.clock()
    with store.db() as db:
        row = db.execute("SELECT value FROM meta WHERE key='consumer_heartbeat'").fetchone()
        old = json.loads(row[0]) if row else {}
        if old.get("state") == state and 0 <= now-old.get("at", 0) < 30:
            return
        db.execute("INSERT OR REPLACE INTO meta VALUES('consumer_heartbeat',?)",
                   (canonical({"state": state, "at": now}),))


def consumer_status(store):
    with store.db() as db:
        row = db.execute("SELECT value FROM meta WHERE key='consumer_heartbeat'").fetchone()
    value = json.loads(row[0]) if row else {}
    age = store.clock()-value["at"] if value else None
    fresh = age is not None and 0 <= age <= 60
    return {"state": value.get("state", "unknown") if fresh else "unknown",
            "active": fresh and value.get("state") == "running",
            "checked_at": value.get("at"), "age_seconds": age,
            "basis": "local_process_heartbeat", "vehicle_online_proven": False}


def impact_page(value, *, scope="events", offset=0, limit=20):
    """Keep global counts and explicit pagination; never silently drop issues."""
    all_issues = value["issues"]
    issues = [i for i in all_issues if scope == "all" or
              i["trigger_id"].startswith("field:" if scope == "fields" else "event:")]
    return {**value, "issues": issues[offset:offset+limit], "scope": scope,
            "total_issues": len(all_issues), "filtered_total": len(issues),
            "reason_counts": dict(Counter(i["reason"] for i in all_issues)),
            "offset": offset, "next_offset": offset+limit if offset+limit < len(issues) else None}


def operation_evidence(store, intent, *, _snapshot_identity=None):
    """Match a later observation for supported checks, without attributing cause.

    Old intents lack a dispatch completion time: creation time cannot be used
    to claim a later effect, since execution may have happened much later.
    """
    outcome = intent["result"] or {}
    accepted = intent["status"] == "acknowledged"
    result = {"status": "command_accepted" if accepted else intent["status"],
              "command_accepted": accepted, "effect_observed": False,
              "causality_proven": False, "completed_at": outcome.get("completed_at")}
    if not accepted:
        if intent["status"] == "prepared" and outcome.get("stage") == "preflight":
            return result | {"status": "blocked_before_dispatch", "command_sent": False,
                             "reason": outcome["precondition"]["reason"]}
        return result
    try:
        connection = store.connection()
    except TeslaError:
        return result | {"reason": "connection_unavailable"}
    if not connection or connection["generation"] != intent["generation"]:
        return result | {"reason": "connection_changed"}
    name = intent["operation"]
    if name not in EFFECT_SECTIONS:
        return result | {"reason": "effect_check_not_implemented"}
    with store.db() as db:
        recorded = db.execute("SELECT data FROM snapshots WHERE vehicle=? AND section=?",
                              (intent["vehicle"], "operation_verified_"+intent["id"])).fetchone()
    invalidation = None
    if recorded:
        evidence = json.loads(recorded[0])
        invalidation = evidence.get('invalidation')
        if invalidation is None:
            observation = evidence["observation"]
            age = store.clock()-observation["source_timestamp"]
            if -0.001 < age < 0:
                age = 0.0
            return evidence | {"observation": observation | {"age_seconds": age, "fresh": 0 <= age <= 120},
                               "verification_basis": "recorded_later_observation", "proves_current_state": False}
        result['historical_observation_invalidation'] = invalidation
    section = EFFECT_SECTIONS[name]
    with store.db() as db:
        row = db.execute("SELECT * FROM snapshots WHERE vehicle=? AND section=?", (intent["vehicle"], section)).fetchone()
    if invalidation and (row is None or row['source_at'] is None or row['source_at'] <= invalidation['source_timestamp']):
        return result | {'reason': 'observation_timestamp_conflict'}
    if row is None:
        return result | {"reason": "no_later_observation"}
    if _snapshot_identity is not None:
        # Internal compare-and-set evidence only: never add raw snapshot data
        # or its digest to a public diagnostic or to recorded provenance.
        _snapshot_identity.update(dict(row))
    from .state_evidence import REST_TIME_CONFLICT
    if row['source'] == REST_TIME_CONFLICT:
        return result | {'reason': 'observation_timestamp_conflict',
                         'observation': {'source': REST_TIME_CONFLICT, 'source_timestamp': row['source_at'],
                                         'received_at': row['received'], 'fresh': False}}
    when, age = row["source_at"], store.clock()-row["source_at"] if row["source_at"] is not None else None
    # REST millisecond timestamps can round a few nanoseconds ahead in float conversion.
    if age is not None and -0.001 < age < 0:
        age = 0.0
    result["observation"] = {"source": row["source"], "source_timestamp": when,
                             "received_at": row["received"], "age_seconds": age,
                             "fresh": age is not None and 0 <= age <= 120}
    if name == "vehicle_wake_up":
        state = json.loads(row["data"]).get("state")
        result["observation"]["state"] = state if state in ("online", "offline", "asleep") else "unknown"
    if outcome.get("completed_at") is None:
        return result | {"reason": "dispatch_time_not_recorded"}
    if when is None or when < outcome["completed_at"] or age < 0 or age > 120:
        return result | {"reason": "observation_not_later_and_fresh"}
    data = json.loads(row["data"])
    checks = {}
    if name == "vehicle_wake_up":
        checks = {"state": "online"}
    elif name == "set_temps":
        checks = {"driver_temp_setting": intent["arguments"].get("driver_temp"),
                  "passenger_temp_setting": intent["arguments"].get("passenger_temp")}
    elif name in ("auto_conditioning_start", "auto_conditioning_stop"):
        checks = {"is_climate_on": name == "auto_conditioning_start"}
    elif name == "set_charge_limit":
        checks = {"charge_limit_soc": intent["arguments"]["percent"]}
    elif name in ("door_lock", "door_unlock"):
        checks = {"locked": name == "door_lock"}
    elif name in ("charge_start", "charge_stop"):
        # 'Complete', 'Disconnected' and absent do not prove a requested stop.
        checks = {"charging_state": "Charging" if name == "charge_start" else "Stopped"}
    elif name == "set_charging_amps":
        # Requested current, not actual draw (which also depends on the charger).
        checks = {"charge_current_request": intent["arguments"]["charging_amps"]}
    elif name in ("charge_port_door_open", "charge_port_door_close"):
        checks = {"charge_port_door_open": name == "charge_port_door_open"}
    elif name == "set_sentry_mode":
        checks = {"sentry_mode": intent["arguments"]["on"]}
    elif name == "close_trunk":
        checks = {"rt": 0}
    elif name == "remote_steering_wheel_heater_request":
        checks = {"steering_wheel_heater": intent["arguments"]["on"]}
    elif name == "remote_auto_steering_wheel_heat_climate_request":
        checks = {"auto_steering_wheel_heat": intent["arguments"]["on"]}
    elif name == "remote_steering_wheel_heat_level_request":
        checks = {"steering_wheel_heat_level": intent["arguments"]["level"]}
    elif name == "remote_seat_heater_request":
        checks = {SEAT_FIELDS[intent["arguments"]["seat_position"]]: intent["arguments"]["level"]}
    elif name == "set_seat_heaters":
        checks = {SEAT_FIELDS[int(seat)]: level for seat, level in intent["arguments"]["levels"].items()}
    if not checks:
        return result | {"reason": "effect_check_not_implemented"}
    def matches(key, expected):
        actual = data.get(key)
        if type(expected) in (int, float):
            return type(actual) in (int, float) and abs(actual-expected) <= 0.1
        return actual is expected if type(expected) is bool else actual == expected
    matched = all(matches(k, v) for k, v in checks.items())
    return result | {"status": "effect_observed" if matched else "command_accepted",
                     "effect_observed": matched, "reason": "matching_later_observation" if matched else "observation_does_not_match",
                     "observation": result["observation"]}


def invalidate_operation_observations(db, ref, section, source_at, now):
    """Disqualify only evidence based on the newly contradicted REST block.

    Keep the original evidence and add a durable annotation. A normal later
    state change is not a contradiction of the earlier observation.
    """
    rows = db.execute("SELECT s.section,s.data,i.operation FROM snapshots s JOIN intents i "
                      "ON s.section='operation_verified_'||i.id AND s.vehicle=i.vehicle "
                      "WHERE s.vehicle=?", (ref,)).fetchall()
    for row in rows:
        if EFFECT_SECTIONS.get(row['operation']) != section:
            continue
        evidence = json.loads(row['data'])
        if evidence.get('observation', {}).get('source_timestamp') != source_at or evidence.get('invalidation'):
            continue
        evidence['invalidation'] = {'reason': 'same_source_time_conflict',
                                    'source_timestamp': source_at, 'detected_at': now}
        db.execute('UPDATE snapshots SET data=? WHERE vehicle=? AND section=?',
                   (canonical(evidence), ref, row['section']))


def record_operation_observations(store, ref, section, *, authorization=None):
    """Keep evidence from an explicitly requested read; never schedule a read.

    Store only the last command of each kind. A later state change must not erase
    a previously observed result, or qualify a command from an old connection.
    """
    names = tuple(name for name, observed_section in EFFECT_SECTIONS.items() if observed_section == section)
    if not names:
        return
    if authorization is not None:
        store.require_authorization(authorization)
    connection = store.connection()
    if not connection:
        return
    for name in names:
        with store.db() as db:
            row = db.execute("SELECT id FROM intents WHERE vehicle=? AND generation=? AND operation=? ORDER BY created DESC,rowid DESC LIMIT 1",
                             (ref, connection["generation"], name)).fetchone()
        if row:
            identity = {}
            intent = store.intent(row[0])
            evidence = operation_evidence(store, intent, _snapshot_identity=identity)
            if evidence["effect_observed"] and evidence.get("verification_basis") != "recorded_later_observation":
                evidence["observed_at"] = store.clock()
                with store.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    if authorization is not None:
                        store.assert_authorization(db, authorization)
                    current_connection = db.execute('SELECT generation,status FROM connection WHERE id=1').fetchone()
                    current = db.execute('SELECT * FROM snapshots WHERE vehicle=? AND section=?', (ref, section)).fetchone()
                    if (not current_connection or current_connection['status'] != 'active'
                            or current_connection['generation'] != intent['generation']
                            or current is None or not identity or dict(current) != identity):
                        continue
                    # Same transaction as the source comparison: a late conflict
                    # either prevents this INSERT or invalidates it afterwards.
                    db.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?)',
                               (ref, 'operation_verified_'+row[0], canonical(evidence),
                                'local_observation_check', store.clock(), store.clock()))
