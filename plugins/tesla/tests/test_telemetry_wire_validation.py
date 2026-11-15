"""Audit regressions: invalid envelopes cannot drive observations or events."""
import json
import pytest
from conftest import VIN
from tesla_plugin.telemetry import typed_value, Telemetry
from tesla_plugin.store import utc

BAD_VALUES = [
 ("TpmsLastSeenPressureTimeFl", {"booleanValue": True}),
 ("TpmsLastSeenPressureTimeFl", {"stringValue": "not-a-timestamp"}),
 ("TpmsLastSeenPressureTimeFl", {"locationValue": {}}),
 ("TpmsLastSeenPressureTimeFl", {"longValue": "-1"}),
 ("DestinationLocation", {"locationValue": {"latitude": 91, "longitude": 181}}),
 ("DestinationLocation", {"locationValue": {"latitude": 10}}),
 ("OriginLocation", {"booleanValue": True}),
 ("DoorState", {"doorValue": {"DriverFront": "open"}}),
 ("DoorState", {"stringValue": "not-a-door-message"}),
 ("BatteryLevel", {"doorValue": 5}),
 ("Locked", {"intValue": False}),
 ("DetailedChargeState", {"doorValue": "DetailedChargeStateCharging"}),
]
@pytest.mark.parametrize("field,envelope", BAD_VALUES)
def test_invalid_wire_values_are_not_observations(field, envelope):
    value, quality = typed_value(field,envelope)
    assert quality != "valid"

@pytest.mark.parametrize("field,envelope,expected",[
 ("Gear",{"doorValue":"ShiftStateP"},"invalid"),
 ("Gear",{"invalid":True},"invalid"),
 ("Gear",{"stringValue":"P"},"valid"),
 ("Gear",{"shiftStateValue":"ShiftStateD"},"valid"),
 ("BatteryLevel",{"doubleValue":50},"valid"),
 ("Locked",{"booleanValue":False},"valid"),
 ("Location",{"locationValue":{"latitude":91,"longitude":181}},"invalid"),
 ("Location",{"locationValue":{"latitude":10,"longitude":20}},"valid"),
 ("TpmsLastSeenPressureTimeFl",{"longValue":"1793329663"},"valid"),
])
def test_controls(field,envelope,expected):
    assert typed_value(field,envelope)[1]==expected

@pytest.mark.parametrize("branch,expected", [("doorValue", []), ("doubleValue", ["battery_low"])])
def test_battery_events_require_a_compatible_branch(store,clock,vehicle_ref,branch,expected):
    with store.db() as db:db.execute("DELETE FROM rules")
    t=Telemetry(store,monotonic=clock)
    t.configure_rule(vehicle_ref,"battery_low",{"threshold":20,"hysteresis":2})
    for index,value in enumerate([25,10]):
        if index:clock.advance(10)
        t.ingest("V",{"vin":VIN,"createdAt":utc(clock()),"data":[{"key":"BatteryLevel","value":{branch:value}}]})
    with store.db() as db:
        assert [r[0] for r in db.execute("SELECT name FROM events")]==expected
        assert db.execute("SELECT count(*) FROM samples WHERE quality='valid'").fetchone()[0]==(2 if expected else 0)

def test_invalid_location_recorded_as_invalid(store,clock,vehicle_ref):
    t=Telemetry(store)
    t.ingest("V",{"vin":VIN,"createdAt":utc(clock()),"data":[{"key":"DestinationLocation","value":{"locationValue":{"latitude":91,"longitude":181}}}]})
    with store.db() as db:
        r=db.execute("SELECT value,quality FROM samples WHERE field='DestinationLocation'").fetchone()
        assert json.loads(r[0]) is None
        assert r[1]=="invalid"


@pytest.mark.parametrize('envelope', [{'intValue': 2**31}, {'longValue': str(2**63)},
    {'floatValue': 1e39}, {'doubleValue': float('inf')}, {'doubleValue': float('nan')}])
def test_scalar_wire_limits_are_not_valid_measurements(envelope):
    assert typed_value('BatteryLevel', envelope) == (None, 'invalid')


def test_complete_door_and_tire_wire_records_keep_their_values():
    doors = {k: False for k in ('DriverFront', 'DriverRear', 'PassengerFront', 'PassengerRear', 'TrunkFront', 'TrunkRear')}
    assert typed_value('DoorState', {'doorValue': doors}) == (doors, 'valid')
    tires = {'frontLeft': True, 'frontRight': False, 'semiMiddleAxleLeft2': False}
    assert typed_value('TpmsHardWarnings', {'tireLocationValue': tires}) == (tires, 'valid')
    assert typed_value('TpmsHardWarnings', {'tireLocationValue': {'frontLeft': True, 'front_left': False}}) == (None, 'invalid')


@pytest.mark.parametrize('field', ['Location', 'OriginLocation', 'DestinationLocation'])
def test_oversized_coordinate_does_not_crash_the_consumer(field):
    assert typed_value(field, {'locationValue': {'latitude': 10**400, 'longitude': 0}}) == (None, 'invalid')

