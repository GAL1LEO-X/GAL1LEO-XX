"""One vocabulary for contextual data discovery; proposals never apply changes."""
CONTEXTS = {
    'charging': {'label': 'Charging', 'preset': 'charging', 'sections': ['charge_state'],
                 'reads': ['charging_history', 'vehicle_nearby_charging_sites'],
                 'limits': ['Tesla history does not guarantee all home or third-party charging sessions.', 'Free stalls and prices are not guaranteed by nearby_charging_sites.']},
    'comfort': {'label': 'Comfort', 'preset': 'comfort', 'sections': ['climate_state'], 'reads': [],
                'limits': ['Command acceptance and an observed effect are separate. Climate is never started automatically.']},
    'park': {'label': 'Gear and parking', 'preset': 'drive_diagnostics', 'sections': ['drive_state', 'vehicle_state', 'charge_state'], 'reads': [],
             'limits': ['Invalid/null Gear does not mean P or asleep. DriveRail and charging explain context but do not authorize commands.', 'Frequent diagnostics for as long as needed; the profile does not expire automatically.']},
    'journey': {'label': 'Trips and navigation', 'preset': 'journeys', 'sections': ['navigation_data', 'drive_state'], 'reads': ['vehicle_nearby_charging_sites'],
                'limits': ['The exposed target may be the next stop. The complete route is unavailable.', 'A P/D/R transition does not prove movement. Location requires dedicated consent and permissions.']},
    'security': {'label': 'Doors and events', 'preset': 'notifications', 'sections': ['vehicle_state'], 'reads': [],
                 'limits': ['Locked describes locks, not physically closed doors.', 'Selection, rule readiness, subscription, delivery and processing are distinct states.']},
}
CHANNELS = {
    'on_demand': {'tool': 'tesla_get_state / tesla_read', 'cost': 'REST/commands excluded from the streaming estimate',
                  'frequency': 'only on an authorized request; no implicit polling or wake command', 'changes_collection': False},
    'telemetry': {'tool': 'tesla_get_collection / tesla_estimate_collection', 'cost': 'estimate based on signals and declared active hours',
                  'frequency': 'requested interval, changes, resend and threshold; actual availability and cadence depend on the vehicle'},
    'history': {'tool': 'tesla_get_history', 'cost': 'local archive read; does not contact Tesla',
                'frequency': 'previously received samples; stable pagination and bounded retention'},
    'events': {'tool': 'tesla_list_triggers / tesla_get_event', 'cost': 'does not change collection on its own',
               'frequency': 'only from valid, consistent evidence; batching and subscription are separate', 'vehicle_actuations': 0},
    'derived': {'tool': 'tesla_get_state / tesla_get_operation', 'cost': 'local processing of available evidence',
                'frequency': 'no new sampling', 'limitations': 'Does not invent measurements, Park, movement or causality.'},
}
