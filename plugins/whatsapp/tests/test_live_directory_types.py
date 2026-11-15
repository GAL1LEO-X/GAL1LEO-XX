"""Actual MCP directory calls with synthetic identities of every chat type."""
from copy import deepcopy

import pytest

from conftest import call


DIRECTORY = [
    ('15550900001@c.us', 'private'),
    ('15550900001@s.whatsapp.net', 'private'),
    ('15550900002@lid', 'private'),
    ('15550900003-123@g.us', 'group'),
    ('status@broadcast', 'status'),
    ('15550900004@newsletter', 'channel'),
    ('15550900005@broadcast', 'broadcast'),
    ('synthetic-unknown', 'unknown'),
]


@pytest.mark.parametrize('operation', [None, 'chats_get_chats', 'chats_get_chats_overview', 'chats_post_chats_overview'])
def test_mcp_live_directory_types_do_not_require_archive_state(app_client, operation):
    app, client = app_client
    service = app.state.service
    # Misleading display names must not determine classification.
    rows = [{'id': identifier, 'name': 'Synthetic private contact' if kind != 'private' else 'Synthetic Status'}
            for identifier, kind in DIRECTORY]
    before = deepcopy(rows)
    requests = []
    def chats(**paging):
        requests.append(('directory', paging))
        return {'chats': deepcopy(rows), 'next_offset': None}
    def request(method, path, **kwargs):
        requests.append((method, path, kwargs))
        return deepcopy(rows)
    service.gateway.chats = chats
    service.gateway.request = request
    if operation:
        arguments = {'body': {'pagination': {'limit': 10}}} if operation.startswith('chats_post') else {'query': {'limit': 10}}
        response = call(client, 'read_whatsapp', {'operation': operation, 'arguments': arguments})['result']
        key = 'result'
    else:
        response = call(client, 'list_live_chats', {'limit': 10})['result']
        key = 'chats'
    assert not response.get('isError'), response
    result = response['structuredContent']
    assert result['source'] == 'live_gateway' and result['mirror_complete'] is False
    assert len(requests) == 1
    assert {row['id']: row.get('chat_type') for row in result[key]} == dict(DIRECTORY)
    assert [row['id'] for row in result[key]] == [identifier for identifier, _ in DIRECTORY]
    for row, (_, kind) in zip(result[key], DIRECTORY, strict=True):
        if kind in ('private', 'group'):
            assert row['archive_state']['known'] is False
            assert row['archive_state']['archived'] is None
        else:
            assert 'archive_state' not in row
    assert rows == before
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0


def test_directory_enrichment_preserves_non_chat_rows(app_client):
    app, _ = app_client
    rows = [None, {'name': 'Synthetic without ID'}, {'id': {'unexpected': 'shape'}}]
    assert app.state.service.with_archive_states({'chats': deepcopy(rows)}) == {'chats': rows}
