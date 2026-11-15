"""Passive, finite MCP transport observations; no request bodies or free text.

Header values describe what arrived, not a validated/negotiated protocol or
method. A bounded JSON error response can supply a protocol error code. Neither
observation changes routing, admission, response bytes or retry behavior.
"""
import json


MARKERS = {'missing', 'multiple', 'other'}
PROTOCOLS = {'2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28'}
METHODS = {
    'initialize', 'ping', 'server/discover', 'tools/list', 'tools/call',
    'resources/list', 'resources/templates/list', 'resources/read',
    'resources/subscribe', 'resources/unsubscribe', 'prompts/list', 'prompts/get',
    'logging/setLevel', 'completion/complete', 'notifications/initialized',
    'notifications/cancelled', 'notifications/progress', 'events/list',
    'events/subscribe', 'events/unsubscribe', 'events/subscriptions/list',
}
# The pinned SDK's standard/spec-defined codes, not an arbitrary signed number.
RPC_ERROR_CODES = {-32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022, -32042}
ENUM_FIELDS = {
    'mcp_protocol_header': PROTOCOLS | MARKERS,
    'mcp_method_header': METHODS | MARKERS,
    'mcp_error_observation': {'jsonrpc', 'other_code', 'not_jsonrpc', 'invalid_json',
                              'not_json', 'too_large', 'incomplete'},
}
ERROR_BODY_LIMIT = 8192


def finite_header(scope, name, allowed):
    found = None
    for key, value in scope.get('headers', ()):
        if key.lower() != name:
            continue
        if found is not None:
            return 'multiple'
        # Lookup before decoding; unknown header text never enters a log record.
        found = next((item for item in allowed if value == item.encode('ascii')), 'other')
    return found if found is not None else 'missing'


class MCPObservation:
    def __init__(self, scope):
        self.fields = {
            'mcp_protocol_header': finite_header(scope, b'mcp-protocol-version', PROTOCOLS),
            'mcp_method_header': finite_header(scope, b'mcp-method', METHODS),
        }
        self.body = None

    def start(self, message):
        if message['status'] < 400:
            return
        types = [v.split(b';', 1)[0].strip().lower() for k, v in message.get('headers', ())
                 if k.lower() == b'content-type']
        if types == [b'application/json']:
            self.body = bytearray()
            self.fields['mcp_error_observation'] = 'incomplete'
        else:
            self.fields['mcp_error_observation'] = 'not_json'

    def chunk(self, message):
        if self.body is None:
            return
        chunk = message.get('body', b'')
        if len(self.body) + len(chunk) > ERROR_BODY_LIMIT:
            self.body = None
            self.fields['mcp_error_observation'] = 'too_large'
            return
        self.body.extend(chunk)
        if message.get('more_body', False):
            return
        body, self.body = self.body, None
        try:
            value = json.loads(body)
        except (ValueError, RecursionError):
            self.fields['mcp_error_observation'] = 'invalid_json'
            return
        error = value.get('error') if isinstance(value, dict) and value.get('jsonrpc') == '2.0' else None
        if not isinstance(error, dict) or type(error.get('code')) is not int:
            self.fields['mcp_error_observation'] = 'not_jsonrpc'
        elif error['code'] not in RPC_ERROR_CODES:
            self.fields['mcp_error_observation'] = 'other_code'
        else:
            self.fields['mcp_error_observation'] = 'jsonrpc'
            self.fields['rpc_error_code'] = error['code']
