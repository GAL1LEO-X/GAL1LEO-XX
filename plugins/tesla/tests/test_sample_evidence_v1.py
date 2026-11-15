"""Synthetic durable observations and privacy regressions for schema 3."""
import json
from types import SimpleNamespace

import pytest

from conftest import VIN
from test_telemetry_events import payload
from tesla_plugin.sample_evidence import enrich_history, history_provenance, view
from tesla_plugin.store import Store, canonical
from tesla_plugin.telemetry import Telemetry, consume_record
from tesla_plugin.telemetry_values import CONTRACT_VERSION, DECODER_VERSION, decode_evidence
from tesla_plugin.trigger_catalog import FIELD_MAP


def evidence_rows(store, table):
    with store.db() as db:
        return [dict(row) for row in db.execute('SELECT * FROM '+table)]


def test_kafka_observation_keeps_safe_provenance_and_original_times(store, vehicle_ref, clock):
    original = clock()-30
    frame = payload(clock, {'BatteryLevel': 0, 'Locked': False}, when=original)
    # Transport offsets and envelope metadata are not diagnostic provenance.
    frame['private_receiver_metadata'] = 'synthetic-private-marker'
    record = SimpleNamespace(value=canonical(frame).encode(), key=VIN.encode(),
                             headers=[('vin', VIN.encode()), ('txtype', b'V')],
                             topic='synthetic-private-topic', partition=1, offset=99)
    consume_record(Telemetry(store), record)
    battery = view(store, vehicle_ref, 'BatteryLevel')['current_observation']
    assert battery['value'] == 0 and battery['quality'] == battery['status'] == 'valid'
    assert battery['source_timestamp'] == pytest.approx(original)
    assert battery['received_at'] == clock()
    assert battery['age_seconds'] == pytest.approx(30)
    assert battery['provenance'] == {
        'status': 'recorded', 'source': 'fleet_telemetry', 'source_transport': 'kafka',
        'quality_reason': 'recognized_value', 'decoder_version': DECODER_VERSION,
        'contract_version': CONTRACT_VERSION, 'oneof_branch': 'double_value', 'raw_payload_retained': False,
    }
    assert view(store, vehicle_ref, 'Locked')['current_observation']['value'] is False
    saved = json.dumps(evidence_rows(store, 'sample_provenance')+evidence_rows(store, 'latest_provenance'))
    assert 'synthetic-private' not in saved and VIN not in saved


@pytest.mark.parametrize('envelope,quality,reason,branch', [
    ({'invalid': True}, 'invalid', 'invalid_branch_received', 'invalid'),
    ({'invalid': False}, 'invalid', 'invalid_branch_received', 'invalid'),
    ({'synthetic-private-marker': {'latitude': 48.2, 'longitude': 16.3}}, 'invalid', 'unrecognized_oneof_branch', None),
    ({'stringValue': 'synthetic-private-enum'}, 'enum_unknown', 'enum_value_unknown_or_unavailable', 'string_value'),
    ({'shiftStateValue': 'ShiftStateUnknown'}, 'enum_unknown', 'enum_value_unknown_or_unavailable', 'shift_state_value'),
    ({'doubleValue': 1}, 'invalid', 'invalid_value_for_contract', 'double_value'),
    ({'stringValue': 'P', 'invalid': True}, 'invalid', 'invalid_value_envelope', None),
    ({'SHIFT_STATE_VALUE': 'ShiftStateP'}, 'invalid', 'unrecognized_oneof_branch', None),
    (None, 'invalid', 'invalid_value_envelope', None),
    ({}, 'invalid', 'invalid_value_envelope', None),
])
def test_per_sample_reasons_do_not_copy_private_raw_content(store, vehicle_ref, clock, envelope, quality, reason, branch):
    frame = payload(clock, {'Gear': None})
    frame['data'][0]['value'] = envelope
    Telemetry(store).ingest('V', frame, source_id='synthetic-private-source', source_transport='synthetic-private-transport')
    current = view(store, vehicle_ref, 'Gear')['current_observation']
    assert current['value'] is None and current['quality'] == quality
    assert current['provenance']['quality_reason'] == reason
    assert current['provenance']['oneof_branch'] == branch
    assert current['provenance']['source_transport'] == 'unknown'
    saved = json.dumps(evidence_rows(store, 'sample_provenance')+evidence_rows(store, 'latest_provenance'))
    assert 'synthetic-private' not in saved
    assert 'latitude' not in saved and 'longitude' not in saved and VIN not in saved


def test_malformed_then_old_then_restart_preserve_distinct_source_and_receive_times(store, settings, vehicle_ref, clock):
    telemetry = Telemetry(store)
    start = clock()
    original = payload(clock, {'BatteryLevel': 50})
    telemetry.ingest('V', original)
    clock.advance(10)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': None}))
    clock.advance(5)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 49}, when=start-60))
    restarted = Store(settings, clock=clock)
    assert restarted.migration_backup is None
    assert Telemetry(restarted).ingest('V', original | {'isResend': True})['status'] == 'duplicate'
    state = view(restarted, vehicle_ref, 'BatteryLevel')
    assert state['current_observation']['value'] is None
    assert state['current_observation']['quality'] == 'invalid'
    assert state['current_observation']['source_timestamp'] == pytest.approx(start+10)
    assert state['current_observation']['received_at'] == pytest.approx(start+10)
    assert state['last_valid_observation']['value'] == 50
    assert state['last_valid_observation']['age_seconds'] == pytest.approx(15)
    with restarted.db() as db:
        rows = db.execute('SELECT * FROM samples ORDER BY source_at').fetchall()
        assert len(rows) == 3
        assert rows[0]['source_at'] == pytest.approx(start-60)
        assert rows[0]['received'] == pytest.approx(start+15)
        assert db.execute('SELECT count(*) FROM sample_provenance').fetchone()[0] == 3
    assert state['historical_observation_used_as_current'] is False


def test_conflicting_timestamp_never_becomes_last_valid_and_keeps_both_acquisitions(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 40}))
    clock.advance(1)
    timestamp = clock()
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 41}))
    clock.advance(1)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 42}, when=timestamp))
    state = view(store, vehicle_ref, 'BatteryLevel')
    current = state['current_observation']
    assert current['value'] is None and current['quality'] == 'time_conflict'
    assert current['provenance']['quality_reason'] == 'same_source_time_conflict'
    assert current['provenance']['oneof_branch'] is None
    assert state['last_valid_observation']['value'] == 40
    with store.db() as db:
        rows = db.execute('SELECT * FROM samples WHERE source_at=?', (current['source_timestamp'],)).fetchall()
        evidence = history_provenance(db, [row['id'] for row in rows])
    history = [enrich_history(row, clock(), evidence[row['id']]) for row in rows]
    assert {row['value'] for row in history} == {41, 42}
    assert all(row['quality'] == 'valid' and row['status'] == 'time_conflict' and row['timestamp_conflict'] for row in history)


def test_late_conflict_is_excluded_from_existing_history_snapshot(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    timestamp = clock()
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 41}))
    with store.db() as db:
        row = db.execute("SELECT * FROM samples WHERE field='BatteryLevel'").fetchone()
        watermark = db.execute('SELECT max(rowid) FROM samples').fetchone()[0]
    snapshot_at = clock()
    clock.advance(1)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 42}, when=timestamp))
    with store.db() as db:
        bounded = history_provenance(db, [row['id']], watermark=watermark, as_of=snapshot_at)
        current = history_provenance(db, [row['id']])
    assert enrich_history(row, clock(), bounded[row['id']])['timestamp_conflict'] is False
    assert enrich_history(row, clock(), current[row['id']])['timestamp_conflict'] is True


def test_old_rows_and_replays_do_not_invent_provenance(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    frame = payload(clock, {'BatteryLevel': 50})
    telemetry.ingest('V', frame)
    with store.db() as db:
        db.execute('DELETE FROM sample_provenance')
        db.execute('DELETE FROM latest_provenance')
        db.execute('DELETE FROM ingest')
    # The historical row already exists. Different raw spellings do not create
    # proof of the decoder or transport that produced that original row.
    frame['data'][0]['value'] = {'int_value': 50}
    telemetry.ingest('V', frame)
    state = view(store, vehicle_ref, 'BatteryLevel')
    for key in ('current_observation', 'last_valid_observation'):
        assert state[key]['provenance']['status'] == 'unavailable'
        assert state[key]['provenance']['decoder_version'] is None
    assert evidence_rows(store, 'sample_provenance') == []
    with store.db() as db:
        row = db.execute('SELECT * FROM samples').fetchone()
        mapped = history_provenance(db, [row['id']])
    assert enrich_history(row, clock(), mapped[row['id']])['provenance']['status'] == 'unavailable'


def test_current_provenance_survives_history_retention_and_remains_stale(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 50}))
    clock.advance((store.settings.history_days+1)*86400)
    store.prune()
    state = view(store, vehicle_ref, 'BatteryLevel')
    assert evidence_rows(store, 'sample_provenance') == []
    assert state['last_valid_observation'] is None
    assert state['current_observation']['quality'] == 'valid'
    assert state['current_observation']['status'] == 'stale'
    assert state['current_observation']['provenance']['status'] == 'recorded'


def test_invalid_quality_and_staleness_remain_separate(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': None}))
    clock.advance(500)
    current = view(store, vehicle_ref, 'BatteryLevel')['current_observation']
    assert current['quality'] == current['status'] == 'invalid'
    assert current['freshness'] == 'stale'
    assert current['value'] is None


def test_scope_excludes_historical_fallback_without_rewriting_current(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': 50}))
    clock.advance(1)
    telemetry.ingest('V', payload(clock, {'BatteryLevel': None}))
    state = view(store, vehicle_ref, 'BatteryLevel', include_history=False)
    assert state['history_access'] == 'scope_required'
    assert state['current_observation']['quality'] == 'invalid'
    assert state['last_valid_observation'] is None


@pytest.mark.parametrize('remove', ['disconnect', 'revoked'])
def test_provenance_follows_authorized_vehicle_data_removal(store, vehicle_ref, clock, remove):
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 50}))
    if remove == 'disconnect':
        store.disconnect()
    else:
        store.save_vehicles([])
    assert evidence_rows(store, 'sample_provenance') == []
    assert evidence_rows(store, 'latest_provenance') == []


def test_external_legacy_row_change_cannot_inherit_current_provenance(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 50}))
    with store.db() as db:
        db.execute("UPDATE latest SET value='51' WHERE field='BatteryLevel'")
    current = view(store, vehicle_ref, 'BatteryLevel')['current_observation']
    assert current['value'] == 51
    assert current['provenance']['status'] == 'unavailable'


def test_spatial_envelope_is_not_retained_as_provenance_when_field_is_withheld(store, vehicle_ref, clock):
    with store.db() as db:
        scopes = json.loads(db.execute('SELECT scopes FROM connection').fetchone()[0])
        db.execute('UPDATE connection SET scopes=?', (canonical([s for s in scopes if s != 'vehicle_location']),))
    Telemetry(store).ingest('V', payload(clock, {'Location': {'latitude': 48.2, 'longitude': 16.3}}))
    assert evidence_rows(store, 'sample_provenance') == []
    assert evidence_rows(store, 'latest_provenance') == []


def test_proto_only_field_records_unqualified_contract_without_inventing_meaning():
    spec = next(spec for spec in FIELD_MAP.values() if spec.get('value_contract') == 'protobuf_oneof_only')
    value, quality, evidence = decode_evidence(spec, {'double_value': 0})
    assert value == 0 and quality == 'unqualified'
    assert evidence['quality_reason'] == 'field_value_contract_unavailable'


@pytest.mark.parametrize('remove', ['disconnect', 'revoked', 'retention'])
def test_unresolved_collection_obligations_survive_local_cleanup(store, vehicle_ref, clock, remove):
    with store.db() as db:
        for status in ('active', 'blocked', 'restored_verified', 'superseded', 'cancelled', 'start_rejected'):
            db.execute('INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,updated) VALUES(?,?,?,?,?,?)',
                       ('intent_'+status, vehicle_ref, '{}', 1, status, clock()))
    if remove == 'disconnect':
        store.disconnect()
    elif remove == 'revoked':
        store.save_vehicles([])
    else:
        clock.advance((store.settings.history_days+1)*86400)
        store.prune()
    with store.db() as db:
        retained = db.execute('SELECT * FROM temporary_collections').fetchall()
        assert {row['intent_id'] for row in retained} == {'intent_active', 'intent_blocked'}
        if remove == 'retention':
            assert {row['status'] for row in retained} == {'active', 'blocked'}
        else:
            assert all(row['status'] == 'blocked' and row['next_check'] == 1e30 for row in retained)


def test_retention_keeps_intents_needed_for_unresolved_restoration(store, vehicle_ref, clock):
    with store.db() as db:
        for identifier in ('start', 'restore', 'finished'):
            db.execute('INSERT INTO intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       (identifier, 'key_'+identifier, 'fingerprint', vehicle_ref, 'vehicle_fleet_telemetry_config_create',
                        '{}', '[]', 1, clock(), clock()+600, 'acknowledged', '{}'))
        db.execute('INSERT INTO temporary_collections(intent_id,vehicle,plan,generation,status,restore_intent,updated) VALUES(?,?,?,?,?,?,?)',
                   ('start', vehicle_ref, '{}', 1, 'restore_pending', 'restore', clock()))
    clock.advance((store.settings.history_days+1)*86400)
    store.prune()
    with store.db() as db:
        assert {row[0] for row in db.execute('SELECT id FROM intents')} == {'start', 'restore'}


@pytest.mark.parametrize('age,status', [(120, 'valid'), (121, 'stale')])
def test_default_freshness_boundary_matches_state_without_changing_quality(store, vehicle_ref, clock, age, status):
    clock.value = 1800000000
    Telemetry(store).ingest('V', payload(clock, {'BatteryLevel': 50}))
    clock.advance(age)
    state = view(store, vehicle_ref, 'BatteryLevel')
    assert state['current_observation']['quality'] == 'valid'
    assert state['current_observation']['status'] == status
    with store.db() as db:
        row = db.execute('SELECT * FROM samples').fetchone()
    assert enrich_history(row, clock())['status'] == status


def test_shared_metadata_uses_documented_units_and_semantics(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', payload(clock, {'InsideTemp': 21, 'VehicleSpeed': 10, 'ChargeRateMilePerHour': -1}))
    assert view(store, vehicle_ref, 'InsideTemp')['unit'] == 'C'
    assert view(store, vehicle_ref, 'VehicleSpeed')['unit'] == 'mph'
    assert view(store, vehicle_ref, 'RouteLine')['unit'] is None
    current = view(store, vehicle_ref, 'ChargeRateMilePerHour')['current_observation']
    assert current['value'] == -1 and current['quality'] == 'valid'
    assert current['payload_quality_is_not_measurement_freshness'] is True
    assert current['semantics']['warnings'] == ['negative_rate_semantics_unverified_do_not_treat_as_physical_rate']
