"""Presentation helpers for the private owner console; no network or actions."""
from datetime import datetime
from html import escape
import json
from zoneinfo import ZoneInfo

ICONS = {
    "car": '<path d="m5 7 2-4h10l2 4M4 8h16l1 9H3l1-9Zm1 9v3m14-3v3M6 12h2m8 0h2"/>',
    "battery": '<rect x="3" y="6" width="16" height="12" rx="2"/><path d="M22 10v4M7 10v4m4-4v4"/>',
    "bolt": '<path d="m13 2-9 12h7l-1 8 10-13h-7l1-7Z"/>',
    "lock": '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v3"/>',
    "climate": '<path d="M12 2v20M3.3 7l17.4 10M3.3 17 20.7 7M9 4l3 3 3-3M9 20l3-3 3 3M4 10l4-1-1-4m10 14-1-4 4-1M4 14l4 1-1 4m10-14-1 4 4 1"/>',
    "outside": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1 1m12 12 1 1M5 19l1-1M18 6l1-1"/>',
    "software": '<path d="M4 17h16M8 21h8m-4-4v4"/><rect x="3" y="3" width="18" height="14" rx="2"/>',
    "arrow": '<path d="M5 12h14m-6-6 6 6-6 6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "settings": '<path d="M4 7h16M4 17h16"/><circle cx="8" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
    "shield": '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
    "check": '<path d="m5 12 4 4L19 6"/>',
    "logout": '<path d="M10 4H4v16h6m4-12 4 4-4 4m-6-4h10"/>',
}


def icon(name):
    return ('<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" '
            'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
            + ICONS.get(name, ICONS["car"]) + '</svg>')


def local_time(timestamp, timezone, *, date=True):
    return datetime.fromtimestamp(timestamp, ZoneInfo(timezone)).strftime("%d/%m · %H:%M:%S %Z" if date else "%H:%M")


PARAMETERS = {"percent": 'Charge limit', "charging_amps": 'Charging current',
              "driver_temp": 'Driver temperature', "passenger_temp": 'Passenger temperature',
              "on": 'Activation', "enable": 'Activation', "enabled": 'Activation', "pin": "PIN",
              "password": "Password", "volume": "Volume", "seat_position": 'Seat position',
              "level": 'Level', "which_trunk": 'Compartment', "mode": 'Mode', "command": 'Command'}
UNITS = {"percent": "%", "charging_amps": "A", "driver_temp": "°C", "passenger_temp": "°C"}


def parameters(arguments):
    """Show the exact prepared values without exposing the API as the main UI."""
    if not arguments:
        return '<p class="muted">This action requires no additional parameters.</p>'
    rows = []
    for key, value in arguments.items():
        label = PARAMETERS.get(key, key.replace("_", " ").capitalize())
        if isinstance(value, (dict, list)):
            rendered = '<pre>'+escape(json.dumps(value, ensure_ascii=False, indent=2))+'</pre>'
        else:
            if type(value) is bool:
                text = 'Yes' if value else "No"
            elif value is None:
                text = 'Unspecified'
            else:
                text = str(value)
            rendered = escape(text)+(' <span class="unit">'+UNITS[key]+'</span>' if key in UNITS else '')
        rows.append(f'<div><dt>{escape(label)}</dt><dd>{rendered}</dd></div>')
    return '<dl class="parameters">'+''.join(rows)+'</dl>'
