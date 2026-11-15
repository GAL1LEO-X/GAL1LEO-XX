"""Apply reviewed SDK additions after the historical catalogue import (idempotent)."""
from copy import deepcopy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PIN = 'fc5a1910ad45c42921d541089e3e366d0b897f52'
SOURCE = 'https://github.com/teslamotors/vehicle-command/blob/'+PIN+'/pkg/vehicle/'
EXTENSION = 'gal1leo-vehicle-command/2'
PROTOCOL_SOURCE = 'https://github.com/Teslemetry/tesla-protocol/blob/452c0ddd10c77e09c97f9acf4d3cc7e833cc802b/proto/command/car_server.proto'


def extend_telemetry(fields):
    # The prose table calls these three types simply "enum". The historical
    # importer incorrectly resolved every generic enum to CarTypeValue. Resolve
    # them using the official pinned vehicle_data.proto (bd076fe, lines 493–520).
    enums = {
        'SemitruckPassengerSeatFoldPosition': ('SeatFoldPosition',
            ('Unknown', 'SNA', 'Faulted', 'NotConfigured', 'Folded', 'Unfolded')),
        'SemitruckTractorParkBrakeStatus': ('TractorAirStatus',
            ('Unknown', 'NotAvailable', 'Error', 'Charged', 'BuildingPressureIntermediate',
             'ExhaustingPressureIntermediate', 'Exhausted')),
        'SemitruckTrailerParkBrakeStatus': ('TrailerAirStatus',
            ('Unknown', 'SNA', 'Invalid', 'BobtailMode', 'Charged', 'BuildingPressureIntermediate',
             'ExhaustingPressureIntermediate', 'Exhausted')),
    }
    fields = deepcopy(fields)
    for field in fields:
        name = field['field']
        if name == 'OffroadLightbarPresent':
            field['unit_explicit_in_description'] = ''  # lightbar is not a pressure unit
        if name in ('TonneauOpenPercent', 'TonneauPosition', 'TonneauTentMode'):
            field['hardware_notes'] = 'Cybertruck only'
        field['configurable'] = field['catalog_status'] in ('DOCUMENTED', 'PROTO_ONLY_UNDOCUMENTED') and name != 'RouteLastUpdated'
        field['receiver_supported'] = True
        if field['catalog_status'] == 'PROTO_ONLY_UNDOCUMENTED':
            field['category'] = 'Service'
            field['value_contract'] = 'protobuf_oneof_only'
            field['notes'] = 'Official protocol key; no per-field value type in Available Data. Values are retained with unqualified semantics; not used as valid rule or safety evidence.'
            if name in ('SemiCruiseSpeedLimitMph', 'Cabin12vPortKeepOn', 'Cabin48vPortKeepOn'):
                field['hardware_notes'] = 'Semi only'
        if field['field'] in enums:
            kind, values = enums[field['field']]
            field.update(protobuf_value_type=kind,
                         enum_values='|'.join(kind+value+'='+str(i) for i, value in enumerate(values)))
    names = {row['field'] for row in fields}
    # Partial inputs are used to review isolated type corrections. Only expand
    # a complete imported catalogue with the newly published protocol keys.
    if 'RemoteStartActive' not in names:
        return fields
    for number, name in enumerate(('AccessoryRail', 'PowerTransferStatus', 'AutomaticEmergencyBrakingState',
                                  'RollingResistanceCoefficient', 'LifetimeDcChargeEnergyKwh', 'SemiVehicleMassKg'), 272):
        if name in names:
            row = next(row for row in fields if row['field'] == name)
        else:
            row = deepcopy(next(row for row in fields if row['field'] == 'RemoteStartActive'))
            fields.append(row)
        row.update(field=name, field_id=str(number), configurable=False, receiver_supported=False,
                       minimum_firmware_field='2026.32.300 / 2026.38.6', minimum_client_field='not individually stated',
                       hardware_notes='Semi only' if name == 'SemiVehicleMassKg' else 'field-specific availability not guaranteed',
                       source_proto='https://github.com/teslamotors/fleet-telemetry/blob/18800f7738757a741479e71b38ece584d363ef2d/protos/vehicle_data.proto',
                       snapshot_commit='18800f7738757a741479e71b38ece584d363ef2d', retrieved_utc='2026-10-31',
                   notes='Official protocol key. Requires a receiver upgrade and compatible vehicle firmware; catalogued, not executable with the pinned receiver.')
    return fields


def extend(catalogue):
    rows = {row['id']: row for row in catalogue['operations']}
    def add(name, description, properties, source, *, extension=False, scopes=None):
        row = deepcopy(rows['set_sentry_mode'])
        row.update(id=name, path='/api/1/vehicles/{vin}/command/'+name,
                   description=description, schema={'type':'object', 'properties':properties,
                   'required':list(properties), 'additionalProperties':False},
                   parameter_locations={k:'body' for k in properties}, source=source,
                   scopes=scopes or ['vehicle_cmds'], reason='Signed transport implemented; firmware/hardware and physical effect require separate qualification')
        if extension:
            row.update(category='sdk-extensions', proxy_extension=EXTENSION,
                       reason='Requires the versioned GAL1LEO proxy adapter; public SDK helper, not a Tesla REST endpoint')
        rows[name] = row
    for name, text in [('set_low_power_mode','Enable/disable low power mode; this may limit Sentry Mode and parked features'),
                       ('keep_accessory_power_mode','Keep accessories powered after exit; increases consumption and may be limited by low power mode')]:
        add(name, text, {'enable':{'type':'boolean'}}, SOURCE+'charge.go')
    add('close_trunk', 'Explicitly close only the powered rear trunk; does not operate the front trunk', {}, SOURCE+'actions.go', extension=True)
    for name, label in [('batch_remove_charge_schedules','charging'),('batch_remove_precondition_schedules','preconditioning')]:
        add(name, 'Delete ALL schedules for '+label+' in the selected categories; no automatic restoration',
            {k:{'type':'boolean'} for k in ('home','work','other')}, SOURCE+'charge.go', extension=True,
            scopes=['vehicle_charging_cmds','vehicle_cmds'])
        rows[name]['schema']['anyOf'] = [{'properties':{k:{'const':True}}} for k in ('home','work','other')]
    add('set_seat_heaters', 'Set multiple seat heaters in one signed action; levels 0–3 and supported Model Y Legacy seat positions only',
        {'levels':{'type':'object', 'properties':{str(k):{'type':'integer','minimum':0,'maximum':3} for k in (0,1,2,4,5)},
                   'additionalProperties':False,'minProperties':1}}, SOURCE+'climate.go', extension=True)
    for name in ('set_climate_keeper_mode', 'set_preconditioning_max'):
        rows[name]['schema']['properties']['manual_override'] = {'type':'boolean'}
        rows[name]['parameter_locations']['manual_override'] = 'body'
    # Match ExtractCommandAction in the pinned proxy. Omission preserves its
    # default; disabling departure scheduling does not require an unused time.
    maximum = rows['set_preconditioning_max']['schema']
    maximum['required'] = [key for key in maximum['required'] if key != 'manual_override']
    departure = rows['set_scheduled_departure']
    departure['schema']['properties']['preconditioning_weekdays_only'] = {'type':'boolean'}
    departure['parameter_locations']['preconditioning_weekdays_only'] = 'body'
    departure['schema']['required'] = ['enable']
    departure['schema']['allOf'] = [{'if': {'properties': {'enable': {'const': True}}, 'required': ['enable']},
                                   'then': {'required': ['departure_time']}}]
    fields = rows['vehicle_fleet_telemetry_config_create']['schema']['properties']['config']['properties']['fields']['properties']
    for name, schema in fields.items():
        schema['properties']['minimum_delta']['type'] = 'number'
        schema['properties']['include_fields'] = {'type':'array', 'items':{'type':'string','pattern':'^[A-Za-z][A-Za-z0-9]*$','maxLength':100}, 'maxItems':len(fields), 'uniqueItems':True}
    extensions = {
        'navigation_gps_request': ['Order: 0 firmware default, 1 replace, 2 prepend, 3 append (public protocol enum, not an index). Existing itinerary cannot be read completely; preservation is not verified.'],
        'navigation_sc_request': ['Use the numeric Supercharger location id returned by nearby charging sites, not its name or a guessed id.', 'Order: 0 firmware default, 1 replace, 2 prepend, 3 append. Complete route preservation is not verified.'],
        'navigation_waypoints_request': ['Send an explicitly approved complete itinerary. No append/preserve parameter; unknown existing stops cannot be reconstructed.', 'Waypoints remain a firmware-interpreted string (for example comma-separated refId: place identifiers); identifiers must be supplied or verified, never invented.', 'Optional destination energy percentages use the public PR 443 contract; the vehicle compatibility is not verified.'],
        'remote_auto_steering_wheel_heat_climate_request': ['Requires an automatic heated steering wheel and active preconditioning or climate keeper. Does not start climate automatically.'],
        'remote_steering_wheel_heat_level_request': ['Levels: 0 off, 1 low, 3 high; 2 is not accepted. Requires supported hardware and active preconditioning or climate keeper.'],
        'remote_boombox': ['Requires external speaker/PWS and supporting firmware/region; vehicle must be parked.', 'Sound 0 is a random fart, 2000 a locate ping. No automatic sound retry or audible-effect inference.'],
        'upcoming_calendar_entries': ['Transmits caller-supplied calendar_data without importing a calendar or interpreting/rewriting the opaque payload. Firmware must accept its encoding.', 'Calendar rendering cannot be observed through the current plugin; acceptance is not display verification.']}
    for name, limitations in extensions.items():
        rows[name].update(availability='supported_transport', proxy_extension=EXTENSION,
                          implementation_status='signed_extension_implemented',
                          reason='Typed public protocol extension with official Tesla signing/session transport; hardware, firmware and physical effect require separate qualification.',
                          contract_source=PROTOCOL_SOURCE, limitations=limitations,
                          official_sdk_native=False)
    notes = {
        'navigation_gps_request':'Order: 0 firmware default, 1 replace, 2 prepend, 3 append. Preservation of existing stops has not been verified on the vehicle.',
        'navigation_sc_request':'Use the verified station identifier. Order: 0 firmware default, 1 replace, 2 prepend, 3 append. Preservation of existing stops remains unverified.',
        'navigation_waypoints_request':'Send only an approved complete route. This action does not reconstruct or automatically preserve unknown existing stops.',
        'remote_auto_steering_wheel_heat_climate_request':'Requires compatible steering-wheel hardware and active climate. This action does not start climate automatically.',
        'remote_steering_wheel_heat_level_request':'Level: 0 off, 1 low, 3 high. Requires compatible steering-wheel hardware and active climate.',
        'remote_boombox':'Play an external sound: 0 random, 2000 locate. Requires Park and a compatible external speaker.',
        'upcoming_calendar_entries':'Send the supplied content without importing a calendar. Accepted encoding and display behavior remain unverified.'}
    for name, note in notes.items():
        rows[name]['owner_note'] = note
    for name in ('navigation_gps_request','navigation_sc_request'):
        rows[name]['schema']['properties']['order'] = {'type':'integer','enum':[0,1,2,3],
            'description':'0 firmware default; 1 replace; 2 prepend; 3 append. Not a stop index. Preservation of existing stops is unverified.'}
    rows['navigation_sc_request']['schema']['properties']['id'] = {'type':'integer','minimum':1,'maximum':9007199254740991,
        'description':'Verified numeric Supercharger location id, exactly representable in JSON transport.'}
    rows['navigation_waypoints_request']['description'] = 'Send an approved complete route; does not automatically add a stop while preserving unknown stops'
    for name,key in [('navigation_waypoints_request','waypoints'),('upcoming_calendar_entries','calendar_data')]:
        rows[name]['schema']['properties'][key].update(maxLength=16384,
             description='UTF-8 string, at most 16384 bytes; firmware interprets the content without automatic transformations.')
    for key in ('destination_start_soe','destination_arrival_soe'):
        rows['navigation_waypoints_request']['schema']['properties'][key] = {'type':'integer','minimum':0,'maximum':100,
            'description':'Optional energy percentage. Omission does not introduce a zero value.'}
        rows['navigation_waypoints_request']['parameter_locations'][key] = 'body'
    for name in ('navigation_gps_request','navigation_waypoints_request'):
        rows[name]['input_permissions']=['tesla:location']
    catalogue['operations'] = list(rows.values())
    catalogue['sdk_extension'] = {'protocol':EXTENSION,'upstream_commit':PIN,
        'signing_sessions_reimplemented':False,'typed_wire_extensions':list(extensions),
        'contract_source':PROTOCOL_SOURCE}
    history = rows['charging_history']['schema']['properties']
    for name in ('startTime', 'endTime'):
        history[name].update(format='date-time',
            description='ISO 8601 with explicit timezone, e.g. 2026-10-27T00:00:00+01:00. No implicit local timezone.')
    history['sortOrder'].update(enum=['ASC','DESC'], description='Requested ascending or descending ordering. Does not establish a default sort field.')
    history['sortBy']['description'] = 'Tesla sorting field. The public contract does not enumerate valid fields or document the default order; do not invent a value.'
    rows['charging_history']['limitations'] = [
        'One page does not establish the most recent sessions without verified ordering.',
        'Tesla billing history does not guarantee coverage of home or third-party charging.']
    nearby = rows['vehicle_nearby_charging_sites']['schema']['properties']
    nearby['radius']['description'] = 'Search radius in miles (Tesla API unit), not kilometers.'
    nearby['count']['description'] = 'Requested result count. The response can contain separate Supercharger and destination-charging lists; no combined limit is applied by the plugin.'
    nearby['detail']['description'] = 'Request site details. Availability, power and tariff fields are not guaranteed in every response.'
    rows['vehicle_nearby_charging_sites']['limitations'] = [
        'Missing stall counts do not mean zero; an empty billing_info does not mean free charging.',
        'site_closed=false does not prove free stalls. Congestion synchronization and response timestamps are separate.']
    return catalogue


def main():
    path=ROOT/'src/tesla_plugin/data/telemetry.json'
    telemetry = extend_telemetry(json.loads(path.read_text()))
    path.write_text(json.dumps(telemetry, ensure_ascii=False, indent=2)+'\n')
    path=ROOT/'src/tesla_plugin/data/operations.json'
    operations = json.loads(path.read_text())
    op = next(row for row in operations['operations'] if row['id'] == 'vehicle_fleet_telemetry_config_create')
    schemas = op['schema']['properties']['config']['properties']['fields']['properties']
    for field in telemetry:
        if field.get('configurable') and field['field'] not in schemas:
            schemas[field['field']] = deepcopy(schemas['BatteryLevel'])
    for field in telemetry:
        if field.get('receiver_supported') is False:
            schemas.pop(field['field'], None)
    path.write_text(json.dumps(extend(operations), ensure_ascii=False, indent=2)+'\n')

if __name__ == '__main__':
    main()
