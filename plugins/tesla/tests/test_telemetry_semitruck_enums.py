"""Independent examples from the pinned Tesla Value oneof, not generated from our catalogue.

Source: teslamotors/fleet-telemetry bd076fe1494841707528449560c4a19d0d426da4,
protos/vehicle_data.proto:493–520 and Value branches 25, 26, 30.
These are protocol tests, not a claim that Model Y has Semi hardware.
"""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

from tesla_plugin.config import SCOPES
from tesla_plugin.telemetry import FIELD_MAP, Telemetry, typed_value
from test_telemetry_events import payload


CASES = [
    ('SemitruckPassengerSeatFoldPosition', 'seatFoldPositionValue', 'seat_fold_position_value',
     'SeatFoldPositionFolded'),
    ('SemitruckTractorParkBrakeStatus', 'tractorAirStatusValue', 'tractor_air_status_value',
     'TractorAirStatusCharged'),
    ('SemitruckTrailerParkBrakeStatus', 'trailerAirStatusValue', 'trailer_air_status_value',
     'TrailerAirStatusCharged'),
]


@pytest.mark.parametrize('field,camel,snake,value', CASES)
@pytest.mark.parametrize('snake_case', [False, True])
def test_official_semitruck_enum_reaches_decoder(field, camel, snake, value, snake_case):
    assert typed_value(field, {snake if snake_case else camel: value}) == (value, 'valid')
    assert typed_value(field, {'invalid': True}) == (None, 'invalid')
    assert typed_value(field, {camel: 'CarTypeModelY'}) == (None, 'enum_unknown')


def test_official_semitruck_enum_survives_ingestion_and_history(service, vehicle_ref, clock):
    frame = payload(clock, {})
    frame['data'] = [{'key': field, 'value': {camel: value}} for field, camel, _, value in CASES]
    Telemetry(service.store).ingest('V', frame)
    fields = [row[0] for row in CASES]
    with service.store.db() as db:
        rows = {row['field']: (json.loads(row['value']), row['quality']) for row in
                db.execute('SELECT * FROM latest WHERE vehicle=?', (vehicle_ref,))}
    assert rows == {field: (value, 'valid') for field, _, _, value in CASES}
    history = service.history(vehicle_ref, fields, clock()-1, clock()+1, SCOPES)
    assert {row['field']: (row['value'], row['quality']) for row in history['samples']} == rows


def test_import_correction_is_idempotent_and_preserves_unrelated_fields():
    spec = importlib.util.spec_from_file_location('reviewed_catalogue',
        Path(__file__).resolve().parents[1]/'tools/extend_catalogue.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fields = [deepcopy(FIELD_MAP[field]) for field, *_ in CASES] + [deepcopy(FIELD_MAP['CarType'])]
    for row in fields[:-1]:
        row.update(protobuf_value_type='CarTypeValue', enum_values=FIELD_MAP['CarType']['enum_values'])
    original = deepcopy(fields)
    corrected = module.extend_telemetry(fields)
    assert fields == original
    assert corrected[-1] == original[-1]
    assert corrected == module.extend_telemetry(corrected)
    for row in corrected[:-1]:
        assert row['protobuf_value_type'] == FIELD_MAP[row['field']]['protobuf_value_type']
        assert row['enum_values'] == FIELD_MAP[row['field']]['enum_values']
