import math
import pytest
from jsonschema import Draft202012Validator
from tesla_plugin.catalogue import OPERATIONS, FIELDS, validate, public_schema
from tesla_plugin.errors import TeslaError


def test_public_inventory_and_explicit_limitations():
    assert len(OPERATIONS) == 131
    assert len([x for x in OPERATIONS.values() if x["category"] == "vehicle-commands"]) == 74
    assert len(FIELDS) == 278
    assert OPERATIONS["navigation_request"]["transport"] == "fleet"
    assert OPERATIONS["remote_boombox"]["availability"] == "supported_transport"
    assert OPERATIONS["remote_boombox"]["proxy_extension"] == "gal1leo-vehicle-command/2"
    assert OPERATIONS["sun_roof_control"]["availability"] == "not_applicable"
    assert OPERATIONS["vehicle_signed_command"]["availability"] == "operator_only"
    for op in OPERATIONS.values():
        Draft202012Validator.check_schema(op["schema"])
        assert op["schema"]["additionalProperties"] is False
        assert "vin" not in op["schema"]["properties"]


@pytest.mark.parametrize("name,args", [
    ("set_temps", {"driver_temp": 21.5, "passenger_temp": 20}),
    ("set_charge_limit", {"percent": 80}),
    ("remote_auto_seat_climate_request", {"auto_seat_position": 1, "auto_climate_on": True}),
    ("remote_auto_seat_climate_request", {"auto_seat_position": 2, "auto_climate_on": False}),
    ("parental_controls_enable_setting", {"setting": "Acceleration", "enable": True}),
    ("parental_controls_enable_setting", {"setting": "TheaterBlocked", "enable": False}),
    ("adjust_volume", {"volume": 10}),
    ("set_valet_mode", {"on": True}),
    ("navigation_request", {"type": "share_ext_content_raw", "value": {"android.intent.extra.TEXT": "Wien Hauptbahnhof"}, "locale": "de-AT", "timestamp_ms": "1792915200000"}),
])
def test_meaningful_valid_parameter_contracts(name, args):
    assert validate(name, args) == args


@pytest.mark.parametrize("name,args", [
    ("set_temps", {"driver_temp": 70, "passenger_temp": 70}),
    ("set_temps", {"driver_temp": math.nan, "passenger_temp": 21}),
    ("set_charge_limit", {"percent": 101}),
    ("set_charge_limit", {"percent": True}),
    ("adjust_volume", {"volume": 11}),
    ("remote_auto_seat_climate_request", {"auto_seat_position": 0, "auto_climate_on": True}),
    ("door_unlock", {"vin": "ANOTHER_VEHICLE"}),
    ("door_unlock", {"url": "https://attacker.invalid"}),
    ("parental_controls_activate", {"pin": "1234"}),
    ("set_valet_mode", {"on": True, "password": "1234"}),
    ("vehicle_drivers_remove", {}),
    ("navigation_request", {"type": "share_ext_content_raw", "value": {"url": "https://attacker.invalid"}, "locale": "de-AT", "timestamp_ms": "1792915200000"}),
])
def test_bad_values_or_secret_chat_input_are_rejected(name, args):
    with pytest.raises(TeslaError) as error:
        validate(name, args)
    assert "1234" not in str(error.value)


def test_scheduling_requires_enabled_boundary():
    args = {"lat": 48.2, "lon": 16.37, "days_of_week": "Weekdays", "start_enabled": True, "end_enabled": False, "enabled": True}
    with pytest.raises(TeslaError):
        validate("add_charge_schedule", args)
    assert validate("add_charge_schedule", args | {"start_time": 1380})["start_time"] == 1380


def test_secure_pin_only_in_owner_execution():
    assert "pin" not in public_schema(OPERATIONS["parental_controls_activate"])["properties"]
    assert validate("parental_controls_activate", {"pin": "0142"}, sensitive=True)["pin"] == "0142"
