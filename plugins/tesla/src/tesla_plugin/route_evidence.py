"""One permission-gated route projection for the panel and MCP.

The parser only describes received geometry. It cannot establish stops, a final
destination, current vehicle position or the physical route driven.
"""

from .sample_evidence import DEFAULT_MAX_AGE_SECONDS, view as sample_view
from .route_geometry import parse_route_line


def view(store, ref, *, location_allowed, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    result = {
        "status": "unavailable",
        "source": "fleet_telemetry",
        "field": "RouteLine",
        "geometry": None,
        "complete_itinerary_verified": False,
        "stop_list_available": False,
        "destination_final_verified": False,
        "current_vehicle_position": False,
    }
    # Guard before a read, not merely before serialization. Keep this shared
    # boundary even though authenticated callers also check their own grants.
    if location_allowed is not True:
        return result | {"reason": "LOCATION_PERMISSION_REQUIRED"}
    evidence = sample_view(store, ref, "RouteLine", include_history=False,
                           max_age_seconds=max_age_seconds)
    observed = evidence.get("current_observation")
    if not observed:
        return result | {"reason": "ROUTE_NOT_OBSERVED"}
    result["observation"] = {key: value for key, value in observed.items() if key != "value"}
    if observed.get("quality") != "valid" or observed.get("status") != "valid":
        return result | {"reason": "ROUTE_NOT_CURRENT_VALID"}
    parsed = parse_route_line(observed.get("value"))
    if parsed["status"] != "available":
        return result | {"reason": parsed["reason"]}
    return result | {"status": "available", "geometry": parsed,
                     "coverage": "partial_route_geometry"}
