"""Structured telemetry privacy across ingestion, stored data and owner UI.

Only synthetic coordinates and offline fixtures; no vehicle requests.
"""
import json
from dataclasses import replace
import re

import pytest
from starlette.testclient import TestClient

from conftest import VIN
from tesla_plugin.config import SCOPES
from tesla_plugin.errors import TeslaError
from tesla_plugin.server import create_app
from tesla_plugin.store import canonical, digest, utc
from tesla_plugin.telemetry import Telemetry
from tesla_plugin.triggers import flush_changes

FIELDS = ('ScheduledDepartureTime', 'LifetimeEnergyGainedRegen', 'GpsAccuracyMeters',
          'LifetimeEnergyChargedKwh', 'BrickSocMinPercent', 'NominalFullPackEnergyKwh',
          'GradeEstimatePercent', 'MaxSpeedToReachDestinationMph', 'SoftwareUpdateAvailable',
          'SoftwareUpdateInProgress', 'RemoteStartActive')
SYNTHETIC_LOCATION = {'latitude': 10.125, 'longitude': 20.875}
WITHOUT_LOCATION = tuple(x for x in SCOPES if x != 'tesla:location')


def change_grant(store, mode):
    with store.db() as db:
        if mode == 'tesla_scope':
            scopes = json.loads(db.execute('SELECT scopes FROM connection WHERE id=1').fetchone()[0])
            db.execute('UPDATE connection SET scopes=? WHERE id=1',
                       (canonical([x for x in scopes if x != 'vehicle_location']),))
        elif mode == 'hide_private':
            row = db.execute('SELECT ref,data FROM vehicles').fetchone()
            data = json.loads(row['data'])
            data['granular_access']['hide_private'] = True
            db.execute('UPDATE vehicles SET data=? WHERE ref=?', (canonical(data), row['ref']))


def ingest(store, clock, field, envelope):
    return Telemetry(store).ingest('V', {'vin': VIN, 'createdAt': utc(clock()),
                                       'data': [{'key': field, 'value': envelope}]})


def legacy_sample(store, clock, ref, field='RemoteStartActive', value=None):
    value = SYNTHETIC_LOCATION if value is None else value
    row = (digest(field + 'legacy'), ref, field, canonical(value), clock(), clock(),
           'unqualified', 'payload_created_at')
    with store.db() as db:
        db.execute('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?)', row)
        db.execute('INSERT OR REPLACE INTO latest VALUES(?,?,?,?,?,?,?)', row[1:])
    return row


def call(client, headers, name, arguments):
    return client.post('/tesla/mcp', headers={**headers, 'mcp-method': 'tools/call', 'mcp-name': name},
                       json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
                           'name': name, 'arguments': arguments, '_meta': {
                               'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                               'io.modelcontextprotocol/clientCapabilities': {}}}}).json()['result']


def no_coordinates(value):
    text = canonical(value)
    assert '10.125' not in text and '20.875' not in text


def test_declared_location_still_requires_location_permission(service, clock, vehicle_ref, fleet):
    with pytest.raises(TeslaError) as caught:
        service.history(vehicle_ref, ['Location'], clock()-1, clock()+1, WITHOUT_LOCATION)
    assert caught.value.code == 'SCOPE_REQUIRED'
    assert fleet.calls == []


@pytest.mark.parametrize('field', FIELDS)
@pytest.mark.parametrize('branch', ['locationValue', 'location_value'])
@pytest.mark.parametrize('mode', ['tesla_scope', 'hide_private'])
def test_ingest_checks_spatial_branch_independently_of_field(store, clock, vehicle_ref, fleet, field, branch, mode):
    change_grant(store, mode)
    ingest(store, clock, field, {branch: SYNTHETIC_LOCATION})
    with store.db() as db:
        assert db.execute('SELECT count(*) FROM samples').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM latest').fetchone()[0] == 0
        assert db.execute('SELECT count(*) FROM trigger_buffer').fetchone()[0] == 0
    assert fleet.calls == []


@pytest.mark.parametrize('field', FIELDS)
@pytest.mark.parametrize('envelope,value', [({'doubleValue': 12.5}, 12.5), ({'booleanValue': False}, False)])
def test_scalar_proto_fields_remain_receivable_unqualified(service, store, clock, vehicle_ref, fleet, field, envelope, value):
    change_grant(store, 'tesla_scope')
    ingest(store, clock, field, envelope)
    rows = service.history(vehicle_ref, [field], clock()-1, clock()+1, WITHOUT_LOCATION)['samples']
    assert len(rows) == 1 and rows[0]['quality'] == 'unqualified' and rows[0]['value'] == value
    assert fleet.calls == []


@pytest.mark.parametrize('mode,code', [('mcp_scope', 'SCOPE_REQUIRED'), ('tesla_scope', 'LOCATION_WITHHELD'), ('hide_private', 'LOCATION_WITHHELD')])
def test_old_history_rows_cannot_bypass_location_permissions(service, store, clock, vehicle_ref, fleet, mode, code):
    original = legacy_sample(store, clock, vehicle_ref)
    change_grant(store, mode)
    scopes = WITHOUT_LOCATION if mode == 'mcp_scope' else SCOPES
    with pytest.raises(TeslaError) as caught:
        service.history(vehicle_ref, ['RemoteStartActive'], clock()-1, clock()+1, scopes)
    assert caught.value.code == code
    with store.db() as db:
        assert tuple(db.execute('SELECT * FROM samples').fetchone()) == original
    assert fleet.calls == []


def test_authorized_spatial_proto_history_stays_unqualified(service, store, clock, vehicle_ref, fleet):
    ingest(store, clock, 'RemoteStartActive', {'locationValue': SYNTHETIC_LOCATION})
    rows = service.history(vehicle_ref, ['RemoteStartActive'], clock()-1, clock()+1, SCOPES)['samples']
    assert rows[0]['value'] == SYNTHETIC_LOCATION and rows[0]['quality'] == 'unqualified'
    assert fleet.calls == []


@pytest.mark.parametrize('shape', ['changes', 'observed', 'other_nested'])
@pytest.mark.parametrize('mode,code', [('mcp_scope', 'SCOPE_REQUIRED'), ('tesla_scope', 'LOCATION_WITHHELD'), ('hide_private', 'LOCATION_WITHHELD')])
def test_old_generic_event_does_not_export_spatial_values(settings, service, headers, store, clock, vehicle_ref, fleet, shape, mode, code):
    observation = {'value': SYNTHETIC_LOCATION, 'quality': 'unqualified', 'source_at': clock(), 'received_at': clock()}
    payload = ({'changes': {'RemoteStartActive': {'before': observation, 'after': None}}} if shape == 'changes'
               else {'observed': {'RemoteStartActive': observation}} if shape == 'observed'
               else {'extra': [{'nested': observation}]})
    event_id = 'evt_' + 'a'*64
    with store.db() as db:
        db.execute('INSERT INTO events VALUES(?,?,?,?,?)',
                   (event_id, 'telemetry_changed', vehicle_ref, clock(), canonical(payload)))
    change_grant(store, mode)
    with TestClient(create_app(settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = call(client, headers(scopes=WITHOUT_LOCATION if mode == 'mcp_scope' else SCOPES),
                        'tesla_get_event', {'event_id': event_id})
    assert response['isError'] is True and response['structuredContent']['code'] == code
    no_coordinates(response)
    with store.db() as db:
        assert json.loads(db.execute('SELECT data FROM events').fetchone()[0]) == payload
    assert fleet.calls == []


@pytest.mark.parametrize('mode', ['tesla_scope', 'hide_private', 'allowed'])
@pytest.mark.parametrize('spatial_position', ['before', 'after'])
def test_buffered_spatial_event_obeys_grants_and_location_kind(store, clock, vehicle_ref, fleet, mode, spatial_position):
    scalar = {'value': True, 'quality': 'unqualified', 'source_at': clock(), 'received_at': clock()}
    spatial = {**scalar, 'value': SYNTHETIC_LOCATION}
    payload = {'before': spatial if spatial_position == 'before' else scalar,
               'after': spatial if spatial_position == 'after' else scalar,
               'first_observed_at': clock(), 'count': 1, 'includes_initial_observation': False}
    with store.db() as db:
        db.execute('INSERT INTO trigger_buffer VALUES(?,?,?,?)',
                   (vehicle_ref, 'RemoteStartActive', clock()-61, canonical(payload)))
    change_grant(store, mode)
    with store.db() as db:
        flush_changes(db, clock())
        events = db.execute('SELECT * FROM events').fetchall()
        assert len(events) == (1 if mode == 'allowed' else 0)
        if events:
            assert events[0]['name'] == 'location_changed'
    assert fleet.calls == []


def test_other_surfaces_are_value_free_or_redacted(settings, service, store, clock, vehicle_ref, fleet, headers):
    legacy_sample(store, clock, vehicle_ref)
    store.snapshot(vehicle_ref, 'vehicle_state', {'sentinel': {'nested': SYNTHETIC_LOCATION}}, 'synthetic', clock())
    change_grant(store, 'tesla_scope')
    with TestClient(create_app(settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        for name, arguments in (
            ('tesla_get_state', {'vehicle_ref': vehicle_ref, 'sections': ['vehicle_state'], 'freshness': 'cached_only'}),
            ('tesla_get_collection', {'vehicle_ref': vehicle_ref, 'refresh': False}),
        ):
            response = call(client, headers(scopes=WITHOUT_LOCATION), name, arguments)
            assert response.get('isError') is not True
            no_coordinates(response)
        login = client.post('/tesla/owner/login', data={'password': 'synthetic-owner-passphrase'}, headers={'origin': 'https://bridge.example'})
        assert login.status_code == 200 and re.search('name="csrf"', login.text)
        for path in ('/tesla/owner', '/tesla/owner/collection/' + vehicle_ref):
            response = client.get(path)
            assert response.status_code == 200
            no_coordinates(response.text)
    assert fleet.calls == []


@pytest.mark.parametrize('mode', ['allowed', 'tesla_scope', 'hide_private', 'mcp_scope'])
def test_owner_snapshot_redaction_uses_current_permissions(settings, service, store, clock, vehicle_ref, fleet, mode):
    # Simulates an already stored provider object; not generated by proto-only ingestion.
    store.snapshot(vehicle_ref, 'vehicle_state', {'odometer': 12345, 'extension': SYNTHETIC_LOCATION}, 'synthetic', clock())
    change_grant(store, mode)
    if mode == 'mcp_scope':
        settings = replace(settings, allowed_scopes=WITHOUT_LOCATION)
        service.settings = settings  # Portal derives settings from the supplied service.
    with TestClient(create_app(settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = client.post('/tesla/owner/login', data={'password': 'synthetic-owner-passphrase'}, headers={'origin': 'https://bridge.example'})
        assert response.status_code == 200
        assert '12345' in response.text  # Ordinary content remains available.
        if mode == 'allowed':
            assert '10.125' in response.text and '20.875' in response.text
        else:
            no_coordinates(response.text)
    with store.db() as db:
        data = json.loads(db.execute("SELECT data FROM snapshots WHERE section='vehicle_state'").fetchone()[0])
        assert data == {'odometer': 12345, 'extension': SYNTHETIC_LOCATION}
    assert fleet.calls == []


def test_authorized_old_event_preserves_payload(settings, service, store, clock, vehicle_ref, fleet, headers):
    payload = {'observed': {'RemoteStartActive': {'value': SYNTHETIC_LOCATION, 'quality': 'unqualified'}}}
    event_id = 'evt_' + 'b'*64
    with store.db() as db:
        db.execute('INSERT INTO events VALUES(?,?,?,?,?)', (event_id, 'telemetry_changed', vehicle_ref, clock(), canonical(payload)))
    with TestClient(create_app(settings, service=service, start_worker=False), base_url='https://bridge.example') as client:
        response = call(client, headers(), 'tesla_get_event', {'event_id': event_id})
    assert response.get('isError') is not True
    # Pagination describes the read projection; authorized observations and
    # retained evidence must remain unchanged, including unqualified values.
    assert response['structuredContent']['data'] == {**payload, 'observed_total': 1, 'next_offset': None}
    with store.db() as db:
        assert db.execute('SELECT data FROM events WHERE id=?', (event_id,)).fetchone()[0] == canonical(payload)
    assert fleet.calls == []


@pytest.mark.parametrize('mode', ['tesla_scope', 'hide_private'])
@pytest.mark.parametrize('branch', ['locationValue', 'location_value'])
def test_malformed_spatial_gear_replaces_prior_park_with_invalid(store, clock, vehicle_ref, fleet, mode, branch):
    from tesla_plugin.gear_evidence import view
    change_grant(store, mode)
    ingest(store, clock, 'Gear', {'shiftStateValue': 'ShiftStateP'})
    assert view(store, vehicle_ref)['status'] == 'verified'
    clock.advance(1)
    ingest(store, clock, 'Gear', {branch: SYNTHETIC_LOCATION})
    current = view(store, vehicle_ref)
    assert current['status'] == 'unknown'
    with store.db() as db:
        row = db.execute("SELECT value,quality FROM latest WHERE field='Gear'").fetchone()
        assert row['quality'] == 'invalid' and json.loads(row['value']) is None
        for row in db.execute("SELECT value FROM samples WHERE field='Gear'"):
            no_coordinates(row['value'])
        for row in db.execute('SELECT data FROM snapshots'):
            no_coordinates(row['data'])
    clock.advance(1)
    ingest(store, clock, 'Gear', {'shiftStateValue': 'ShiftStateP'})
    assert view(store, vehicle_ref)['status'] == 'verified'
    assert fleet.calls == []


@pytest.mark.parametrize('mode', ['tesla_scope', 'hide_private'])
@pytest.mark.parametrize('gear', ['ShiftStateD', 'ShiftStateR', 'ShiftStateN'])
def test_nonpark_evidence_is_preserved_without_location_scope(store, clock, vehicle_ref, fleet, mode, gear):
    from tesla_plugin.gear_evidence import view
    change_grant(store, mode)
    ingest(store, clock, 'Gear', {'shiftStateValue': 'ShiftStateP'})
    clock.advance(1)
    ingest(store, clock, 'Gear', {'shiftStateValue': gear})
    assert view(store, vehicle_ref)['status'] == 'not_park'
    assert fleet.calls == []
