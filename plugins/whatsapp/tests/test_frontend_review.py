"""Portable HTTPS template invariants, independent of private host snapshots."""
from pathlib import Path
import re
import pytest
ROOT = Path(__file__).resolve().parents[3]

@pytest.mark.parametrize('port', ['8820', '8822'])
def test_portable_edge_retains_routes_identity_headers_and_private_log_exclusions(port):
    template = (ROOT / 'plugins/whatsapp/deploy/apache-whatsapp.conf.in').read_text()
    actual = template.replace('__DOMAIN__', 'chat.example.test').replace(':8820', ':' + port)
    assert '__DOMAIN__' not in actual
    assert 'BoxPriorityDSCP' not in actual and 'mod_box_priority' not in actual
    expected = {'/webhooks/': '!', '/mcp': f'http://127.0.0.1:{port}/mcp',
        '/connect': f'http://127.0.0.1:{port}/connect', '/files/': f'http://127.0.0.1:{port}/files/',
        '/assets/': f'http://127.0.0.1:{port}/assets/',
        '/.well-known/oauth-protected-resource': f'http://127.0.0.1:{port}/.well-known/oauth-protected-resource'}
    routes = dict(re.findall(r'^\s*ProxyPass (\S+) (\S+)', actual, re.M))
    assert routes == expected
    reverse = dict(re.findall(r'^\s*ProxyPassReverse (\S+) (\S+)', actual, re.M))
    assert reverse == {key: value for key, value in expected.items() if value != '!'}
    for header in ('X-Forwarded-User', 'X-Forwarded-Email'):
        assert 'RequestHeader unset ' + header in actual
    for required in ('LimitRequestBody 1048576', 'RedirectMatch 302 ^/$ /connect',
            'SSLProtocol -all +TLSv1.2 +TLSv1.3', 'Require all denied',
            'SetEnvIf Request_URI "^/(files/|connect/(callback|api/|qr))" whatsapp_private_download',
            'combined env=!whatsapp_private_download'):
        assert required in actual
