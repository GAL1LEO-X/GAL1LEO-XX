"""Synthetic regressions: wire quality, interpretation and payload age differ."""
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from conftest import VIN
from test_mcp_portal import rpc
from test_subscription_lifecycle import Callback, subscribe
from tesla_plugin.collection_evidence import field_evidence
from tesla_plugin.events import Events
from tesla_plugin.sample_evidence import view as sample_view
from tesla_plugin.server import create_app
from tesla_plugin.store import utc
from tesla_plugin.telemetry import Telemetry, typed_value
from tesla_plugin.telemetry_values import CONTRACT, decode_evidence, plausibility, rule_eligibility, semantics
from tesla_plugin.trigger_catalog import FIELD_MAP


FIXTURE = json.loads((Path(__file__).parent / 'fixtures' /
                     'telemetry-nine-key-qualification-2026-11-03.json').read_text())


def frame(at, values):
    return {'vin': VIN, 'createdAt': utc(at),
            'data': [{'key': key, 'value': envelope} for key, envelope in values.items()]}


def collection_view(now, names):
    config = {'fields': {name: {'interval_seconds': 5} for name in names}}
    return {'remote': {'at': now, 'data': {'config': config, 'synced': True}},
            'saved': config, 'target': {'at': now - 1000, 'data': config}, 'last': None}


def test_nine_keys_have_official_ids_but_no_field_specific_type_contract():
    assert FIXTURE['synthetic_only'] is True
    assert FIXTURE['official_schema']['url'] == CONTRACT['source']
    official_ids = {name: int(number) for name, number in
                    (entry.split('=') for entry in CONTRACT['enums']['Field'].split('|'))}
    assert len(FIXTURE['fields']) == 9
    for item in FIXTURE['fields']:
        spec = FIELD_MAP[item['field']]
        assert official_ids[item['field']] == item['field_id'] == int(spec['field_id'])
        assert spec['value_contract'] == 'protobuf_oneof_only'
        assert spec['documented_type'] == spec['protobuf_value_type'] == ''
        assert item['qualified_value_contract'] is False


@pytest.mark.parametrize('item', FIXTURE['fields'], ids=lambda item: item['field'])
@pytest.mark.parametrize('example', FIXTURE['synthetic_envelopes'])
def test_no_type_or_branch_is_inferred_from_the_field_name(item, example):
    value, quality, evidence = decode_evidence(FIELD_MAP[item['field']], example['envelope'])
    assert value == example['expected_value']
    assert quality == example['expected_quality']
    if quality == 'unqualified':
        assert evidence['quality_reason'] == FIXTURE['qualification_reason']


def test_unqualified_values_survive_ingestion_without_becoming_valid(store, vehicle_ref, clock):
    fields = {item['field']: {'floatValue': 12.5} for item in FIXTURE['fields']}
    Telemetry(store).ingest('V', frame(clock(), fields))
    with store.db() as db:
        samples = db.execute('SELECT field,value,quality FROM samples').fetchall()
        reasons = [r[0] for r in db.execute('SELECT quality_reason FROM sample_provenance')]
    assert len(samples) == 9
    assert all(json.loads(r['value']) == 12.5 and r['quality'] == 'unqualified' for r in samples)
    assert reasons == ['field_value_contract_unavailable'] * 9


@pytest.mark.parametrize('value', [-3276.8, -3276.800048828125])
def test_axle_warning_preserves_wire_value_quality_and_provenance(store, vehicle_ref, clock, value):
    value_before, quality, evidence = decode_evidence(FIELD_MAP['DiAxleSpeedR'], {'floatValue': value})
    assert (value_before, quality, evidence['quality_reason']) == (value, 'valid', 'recognized_value')
    Telemetry(store).ingest('V', frame(clock(), {'DiAxleSpeedR': {'floatValue': value}}))
    current = sample_view(store, vehicle_ref, 'DiAxleSpeedR')['current_observation']
    assert current['value'] == value and current['quality'] == 'valid'
    assert current['provenance']['oneof_branch'] == 'float_value'
    warning = current['semantics']['plausibility']
    assert warning['status'] == 'review_required'
    assert warning['wire_quality_changed'] is warning['value_changed'] is warning['certified_sentinel'] is False
    assert warning['unit'] is None
    assert current['semantics']['rule_eligibility'] == {
        'eligible': False, 'reason': 'local_plausibility_review_required',
        'policy': 'local_exact_axle_pattern_v1', 'scope': 'numeric_threshold'}


@pytest.mark.parametrize('value', [-3276.81, -3276.79, -4000, -1, 0, 235.4, 3276.8])
def test_numeric_pattern_warning_is_not_a_general_negative_or_physical_range_filter(value):
    assert typed_value('DiAxleSpeedR', {'doubleValue': value}) == (value, 'valid')
    assert plausibility('DiAxleSpeedR', value, 'valid') is None
    assert plausibility('DiAxleSpeedF', -3276.8, 'valid') is None
    assert plausibility('DiAxleSpeedR', -3276.8, 'invalid') is None
    assert rule_eligibility('DiAxleSpeedR', value, 'valid')['eligible'] is True


@pytest.mark.parametrize('pattern', [-3276.8, -3276.800048828125])
def test_local_plausibility_policy_blocks_threshold_then_requires_new_baseline(store, vehicle_ref, clock, pattern):
    with store.db() as db:
        db.execute('DELETE FROM rules')
    telemetry = Telemetry(store, monotonic=clock)
    telemetry.configure_rule(vehicle_ref, 'threshold',
                             {'field': 'DiAxleSpeedR', 'direction': 'below', 'threshold': -100, 'hysteresis': 2})

    def ingest(value):
        telemetry.ingest('V', frame(clock(), {'DiAxleSpeedR': {'floatValue': value}}))
        clock.advance(1)

    ingest(10)
    ingest(pattern)  # Wire-valid but excluded from decisions by a local policy.
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM events WHERE name='threshold_crossed'").fetchone()[0] == 0
        assert json.loads(db.execute("SELECT state FROM rules WHERE kind='threshold'").fetchone()[0]) == {}
    ingest(-200)  # New baseline must not cross from the value before the gap.
    with store.db() as db:
        assert db.execute("SELECT count(*) FROM events WHERE name='threshold_crossed'").fetchone()[0] == 0
    ingest(10)  # Rearm using ordinary values, then a normal negative crosses.
    ingest(-200)
    with store.db() as db:
        events = db.execute("SELECT data FROM events WHERE name='threshold_crossed'").fetchall()
        assert len(events) == 1
        assert json.loads(events[0][0])['observed']['DiAxleSpeedR'] == -200
        row = db.execute('SELECT value,quality FROM samples WHERE value=?', (json.dumps(pattern),)).fetchone()
        assert json.loads(row['value']) == pattern and row['quality'] == 'valid'


@pytest.mark.parametrize('speed', [0, 0.62, 1, 65])
def test_speed_observations_alone_do_not_classify_motion_or_park(speed):
    value, quality = typed_value('VehicleSpeed', {'doubleValue': speed})
    assert (value, quality) == (speed, 'valid')
    meaning = semantics('VehicleSpeed', value, 1234, quality)['motion_interpretation']
    assert meaning['status'] == 'not_assessed' and meaning['unit'] == 'mph'
    assert meaning['requires'] == ['field_specific_freshness', 'temporally_coherent_cross_field_evidence']
    assert meaning['zero_or_low_speed_is_not_park_evidence'] is True
    assert meaning['residual_speed_is_not_automatically_zeroed'] is True


@pytest.mark.parametrize('field,value,note', [('DiAxleSpeedR', -3276.8, 'plausibility'),
                                            ('VehicleSpeed', 0.62, 'motion_interpretation')])
@pytest.mark.parametrize('kind', ['field_changed', 'telemetry_changed'])
def test_observational_event_reads_expose_warnings_without_rewriting_frozen_delivery(
        service, vehicle_ref, clock, headers, fleet, field, value, note, kind):
    store = service.store
    with store.db() as db:
        db.execute('DELETE FROM rules')
    subscribe(Events(store, transport=Callback()), vehicle_ref, clock, kinds=[kind])
    telemetry = Telemetry(store, monotonic=clock)
    if kind == 'field_changed':
        telemetry.configure_rule(vehicle_ref, kind, {'field': field})
    telemetry.ingest('V', frame(clock(), {field: {'doubleValue': 10}}))
    clock.advance(1)
    telemetry.ingest('V', frame(clock(), {field: {'doubleValue': value}}))
    if kind == 'telemetry_changed':
        observation = {'value': value, 'quality': 'valid', 'source_at': clock(), 'received_at': clock()}
        with store.db() as db:
            Events.emit(db, vehicle_ref, kind, clock(),
                        {'changes': {field: {'before': None, 'after': observation}}}, clock())
    with store.db() as db:
        event = dict(db.execute('SELECT * FROM events WHERE name=?', (kind,)).fetchone())
        db.execute('UPDATE deliveries SET attempts=1 WHERE event=?', (event['id'],))
        before = [tuple(row) for row in db.execute('SELECT * FROM deliveries WHERE event=?', (event['id'],))]
    assert before  # Exercise an already attempted/frozen body, not an empty table.
    with TestClient(create_app(service.settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = rpc(client, headers(), 'tools/call',
                       {'name': 'tesla_get_event', 'arguments': {'event_id': event['id']}}).json()['result']
    assert not response['isError']
    data = response['structuredContent']['data']
    meaning = data['observed_semantics'][field] if kind == 'field_changed' else data['changes'][field]['after']['semantics']
    assert note in meaning
    assert meaning == sample_view(store, vehicle_ref, field)['current_observation']['semantics']
    with store.db() as db:
        assert db.execute('SELECT data FROM events WHERE id=?', (event['id'],)).fetchone()[0] == event['data']
        assert [tuple(row) for row in db.execute('SELECT * FROM deliveries WHERE event=?', (event['id'],))] == before
    assert fleet.calls == []


def test_collection_counts_freshness_and_quality_independently(store, vehicle_ref, clock):
    telemetry = Telemetry(store)
    telemetry.ingest('V', frame(clock() - 300, {'BatteryLevel': {'doubleValue': 50}}))
    telemetry.ingest('V', frame(clock(), {'VehicleSpeed': {'doubleValue': 0.62},
                                        'TpmsPressureFl': {'invalid': True}}))
    names = ['BatteryLevel', 'VehicleSpeed', 'TpmsPressureFl', 'BrakePedal']
    result = field_evidence(store, vehicle_ref, collection_view(clock(), names), location_authorized=True)
    assert result['summary']['quality'] == {'valid': 2, 'invalid': 1, 'not_observed': 1}
    assert result['summary']['freshness'] == {'fresh': 2, 'stale': 1, 'not_observed': 1}
    assert result['summary']['freshness_policy']['max_age_seconds'] == 120
    assert result['summary']['freshness_policy']['physical_measurement_freshness_verified'] is False
    battery = result['fields']['BatteryLevel']
    assert battery['reception']['status'] == battery['reception']['quality'] == 'valid'
    assert battery['reception']['freshness']['status'] == 'stale'
    assert battery['vehicle_reception_verified'] is True  # reception, not present state
    assert battery['fresh_valid_payload_received'] is False
    assert result['fields']['TpmsPressureFl']['reception']['freshness']['status'] == 'fresh'
    assert result['fields']['TpmsPressureFl']['fresh_valid_payload_received'] is False
    assert result['fields']['VehicleSpeed']['fresh_valid_payload_received'] is True


def test_collection_freshness_boundary_uses_source_time_and_explicit_policy(store, vehicle_ref, clock):
    clock.value = 1800000000
    telemetry = Telemetry(store)
    telemetry.ingest('V', frame(clock() - 30, {'BatteryLevel': {'doubleValue': 50}}))
    telemetry.ingest('V', frame(clock() + 1, {'VehicleSpeed': {'doubleValue': 0}}))
    names = ['BatteryLevel', 'VehicleSpeed']
    at_boundary = field_evidence(store, vehicle_ref, collection_view(clock(), names),
                                 location_authorized=True, max_age_seconds=30)
    assert at_boundary['fields']['BatteryLevel']['reception']['freshness']['status'] == 'fresh'
    assert at_boundary['fields']['VehicleSpeed']['reception']['freshness']['status'] == 'future'
    assert at_boundary['fields']['VehicleSpeed']['fresh_valid_payload_received'] is False
    clock.advance(0.01)
    after_boundary = field_evidence(store, vehicle_ref, collection_view(clock(), names),
                                    location_authorized=True, max_age_seconds=30)
    assert after_boundary['fields']['BatteryLevel']['reception']['freshness']['status'] == 'stale'
    assert after_boundary['summary']['freshness_policy']['max_age_seconds'] == 30


def test_collection_freshness_does_not_reveal_restricted_location(store, vehicle_ref, clock):
    Telemetry(store).ingest('V', frame(clock(), {'Location': {'locationValue': {'latitude': 10, 'longitude': 20}}}))
    result = field_evidence(store, vehicle_ref, collection_view(clock(), ['Location']), location_authorized=False)
    item = result['fields']['Location']
    assert item['reception']['quality'] is item['reception']['source_at'] is item['reception']['age_seconds'] is None
    assert item['reception']['freshness']['status'] == 'permission_required'
    assert item['reception']['observed_cadence']['sample_count'] == 0
    assert result['summary']['freshness'] == {'permission_required': 1}
    assert item['fresh_valid_payload_received'] is False
