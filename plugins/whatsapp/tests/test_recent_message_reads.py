"""MCP recent reads against synthetic WAHA pages, without imports or sends."""
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event

import httpx
import pytest
from starlette.testclient import TestClient

from conftest import call, message, rpc
from sally_whatsapp.gateway import DisconnectedGateway, GatewayUnavailable, Waha
from sally_whatsapp.server import create_app


CHAT = '123456789@g.us'
IDENTIFIER = 'false_123456789@g.us_SYNTHETIC_123456780@c.us'


def provider(service, payload):
    requests = []
    def request(method, path, **kwargs):
        requests.append((method, path, kwargs))
        assert method == 'GET'
        return copy.deepcopy(payload)
    service.gateway.request = request
    return requests


def conversation(client, **arguments):
    return call(client, 'read_conversation', {'chat_id': CHAT, **arguments})['result']


def test_empty_archive_identifies_its_scope_and_points_to_explicit_live_read(app_client):
    app, client = app_client
    service = app.state.service
    requests = provider(service, [{'id': IDENTIFIER, 'timestamp': 100, 'body': 'Synthetic recent content'}])
    service.store.cache_chat_names([{'id': CHAT, 'name': 'Synthetic group'}], 'live_directory')
    result = conversation(client)['structuredContent']
    assert result['messages'] == [] and result['coverage'] == 'acquired_archive_only'
    assert result['reading_guidance']['phone_messages_absent'] == 'unknown'
    assert result['reading_guidance']['history_import_required'] is False
    assert result['reading_guidance']['next_read']['arguments']['source'] == 'live'
    assert requests == []
    result = conversation(client, source='live')['structuredContent']
    assert result['messages'][0]['body'] == 'Synthetic recent content'
    assert result['source'] == 'live_gateway' and result['mirror_complete'] is False
    assert service.store.search()['messages'] == []
    with service.store.db() as db:
        for table in ('history_jobs', 'sends', 'deliveries', 'account_events'):
            assert db.execute('SELECT count(*) FROM ' + table).fetchone()[0] == 0


def test_live_recent_read_with_full_capabilities_uses_get_without_download_or_seen(environment):
    settings, receiver, _, token = environment
    settings = replace(settings, live_account_enabled=True, send_enabled=True,
                       allow_all_destinations=True, account_actions_enabled=True)
    gateway = Waha(settings)
    requests = []
    def respond(request):
        requests.append(request)
        return httpx.Response(200, json=[{'id': IDENTIFIER, 'timestamp': 123, 'body': 'Synthetic edited content'}])
    gateway.client.close()
    gateway.client = httpx.Client(base_url=settings.waha_url, transport=httpx.MockTransport(respond))
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization': 'Bearer ' + token(scope='whatsapp:read'),
                               'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2026-07-28'})
        result = conversation(client, source='live', limit=10, offset=20, after=100, before=200)['structuredContent']
        assert result['messages'][0]['body'] == 'Synthetic edited content'
        assert result['read_receipts_sent'] is False and result['history_imported'] is False
        assert len(requests) == 1 and requests[0].method == 'GET'
        assert requests[0].url.path == '/api/default/chats/' + CHAT + '/messages'
        assert dict(requests[0].url.params) == {
            'limit': '10', 'offset': '20', 'sortBy': 'timestamp', 'sortOrder': 'desc',
            'downloadMedia': 'false', 'filter.timestamp.gte': '100', 'filter.timestamp.lte': '200'}
        tools = rpc(client, 'tools/list')['result']['tools']
        tool = next(item for item in tools if item['name'] == 'read_conversation')
        assert tool['annotations']['readOnlyHint'] and tool['annotations']['openWorldHint']
        assert tool['securitySchemes'] == [{'type': 'oauth2', 'scopes': ['whatsapp:read']}]
        assert len(tools) == 27
        with app.state.service.store.db() as db:
            assert db.execute('SELECT count(*) FROM sends').fetchone()[0] == 0
    assert receiver.requests == []


@pytest.mark.parametrize('count,next_offset', [(0, None), (1, None), (2, 9)])
def test_live_page_exhaustion_does_not_claim_complete_history(app_client, count, next_offset):
    app, client = app_client
    provider(app.state.service, [{'id': f'false_{CHAT}_SYNTHETIC{i}', 'timestamp': 100, 'body': 'Synthetic'} for i in range(count)])
    result = conversation(client, source='live', limit=2, offset=7)['structuredContent']
    assert result['next_offset'] == next_offset and result['next_cursor'] is None
    assert result['page_exhausted'] is (count < 2)
    assert result['history_complete'] is False and result['mirror_complete'] is False
    assert result['coverage'] == 'provider_observation_only'
    assert result['pagination_consistency'] == 'provider_offset_current_observation'


@pytest.mark.parametrize('arguments', [{'query': 'text'}, {'cursor': 'archive-cursor'}, {'after': 10, 'before': 1},
                                        {'chat_id': '../wrong'}])
def test_live_rejects_archive_cursor_or_inapplicable_filters_before_gateway(app_client, arguments):
    app, client = app_client
    requests = provider(app.state.service, [])
    assert conversation(client, source='live', **arguments)['isError']
    assert requests == []


def test_archive_cursor_remains_valid_only_for_archive(app_client):
    app, client = app_client
    for i in range(3):
        app.state.service.store.ingest(message('synthetic-' + str(i), chat=CHAT, timestamp=100 + i), historical=True)
    requests = provider(app.state.service, [])
    first = conversation(client, limit=1)['structuredContent']
    second = conversation(client, limit=1, cursor=first['next_cursor'])['structuredContent']
    assert second['messages'][0]['id'] == 'synthetic-1'
    assert conversation(client, source='live', cursor=first['next_cursor'])['isError']
    assert requests == []


@pytest.mark.parametrize('payload', [{'messages': []}, [None], [{}], [{'id': 42}], [{'id': ''}],
                                    [{'id': 'a'}, {'id': 'b'}]])
def test_live_rejects_malformed_or_oversized_page(app_client, payload):
    app, client = app_client
    provider(app.state.service, payload)
    assert conversation(client, source='live', limit=1)['isError']


@pytest.mark.parametrize('unavailable', [False, True])
def test_unavailable_live_never_falls_back_to_archive(app_client, unavailable):
    app, client = app_client
    service = app.state.service
    service.store.ingest(message(IDENTIFIER, chat=CHAT, text='Synthetic acquired content'))
    if unavailable:
        def request(*args, **kwargs):
            raise GatewayUnavailable('Synthetic gateway unavailable')
        service.gateway.request = request
    else:
        service.gateway = DisconnectedGateway()
    result = conversation(client, source='live')
    assert result['isError']
    assert 'Synthetic acquired content' not in str(result)
    assert 'diagnostic reference' not in str(result)
    assert service.store.message(IDENTIFIER)['body'] == 'Synthetic acquired content'


@pytest.mark.parametrize('event,reason,fields', [
    ('events.DeleteForMe', 'deleted_for_me', {'ChatJID': CHAT, 'MessageID': 'SYNTHETIC', 'IsFromMe': False}),
    ('events.DeleteChat', 'chat_deleted', {'JID': CHAT}),
    ('events.ClearChat', 'clear_chat_coverage_uncertain', {'JID': CHAT, 'Action': {'messageRange': {'messages': [
        {'key': {'remoteJID': CHAT, 'ID': 'SYNTHETIC', 'fromMe': False}}]}}}),
])
def test_live_recent_read_preserves_group_deletion_filters(app_client, event, reason, fields):
    app, client = app_client
    service = app.state.service
    service.store.ingest({'id': 'synthetic-app-state', 'event': 'engine.event', 'engine': 'GOWS',
        'payload': {'event': event, 'data': {**fields, 'Timestamp': '2020-01-01T00:00:00Z', 'FromFullSync': False}}})
    provider(service, [{'id': IDENTIFIER, 'timestamp': 1, 'body': 'Synthetic hidden',
                        'media': {'filename': 'Synthetic hidden'}}])
    assert conversation(client, source='live')['structuredContent']['messages'] == [
        {'id': IDENTIFIER, 'content_state': reason}]


def test_live_recent_read_preserves_verified_alias_and_revoked_quotes(app_client):
    app, client = app_client
    service = app.state.service
    lid, pn = '123456789@lid', '123456789@c.us'
    identifier = 'false_' + lid + '_SYNTHETIC'
    service.store.bind_chat_alias(lid, pn)
    service.store.ingest({'id': 'synthetic-revoke', 'event': 'message.revoked',
                          'payload': {'revokedMessageId': identifier}})
    requests = provider(service, [{'id': f'false_{pn}_NEW', 'timestamp': 100, 'body': 'Synthetic visible edit',
                                  'replyTo': {'id': identifier.replace(lid, pn), 'body': 'Synthetic revoked quote'}}])
    result = conversation(client, chat_id=lid, source='live')['structuredContent']
    assert result['chat_id'] == pn and pn.replace('@', '%40') in requests[0][1]
    assert result['messages'][0]['body'] == 'Synthetic visible edit'
    assert result['messages'][0]['replyTo']['content_state'] == 'revoked'
    assert 'Synthetic revoked quote' not in str(result)


@pytest.mark.parametrize('tool,method,arguments', [
    ('search_messages', 'search', {}), ('read_conversation', 'search', {'chat_id': CHAT}),
    ('list_chats', 'chats', {}), ('get_message', 'message', {'message_id': IDENTIFIER}),
    ('list_account_events', 'list_account_events', {}),
])
def test_archive_reads_leave_mcp_event_loop_responsive(app_client, monkeypatch, tool, method, arguments):
    app, client = app_client
    entered, release = Event(), Event()
    original = getattr(app.state.service.store, method)
    def slow(*args, **kwargs):
        entered.set()
        assert release.wait(5), 'Test did not release the synthetic database read'
        return original(*args, **kwargs)
    monkeypatch.setattr(app.state.service.store, method, slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reading = pool.submit(call, client, tool, arguments)
        try:
            assert entered.wait(3)
            probe = pool.submit(call, client, 'check_event_authorization')
            assert probe.result(timeout=3)['result']['structuredContent']['authorized']
            assert not reading.done()
        finally:
            release.set()
        assert not reading.result(timeout=3)['result'].get('isError')


@pytest.mark.parametrize('boundary', [None, 1200])
def test_live_clear_chat_unknown_boundary_warns_and_never_returns_known_candidates(app_client, boundary):
    from test_clearchat_coverage import clear
    app, client = app_client
    service = app.state.service
    chat = '123456789@c.us'
    service.store.ingest(clear(chat=chat, through=boundary, anchors=('C',)))
    provider(service, [
        {'id': 'false_' + chat + '_C', 'timestamp': 1200, 'body': 'Synthetic excluded anchor'},
        {'id': 'false_' + chat + '_F', 'timestamp': 1300, 'body': 'Synthetic remaining provider observation'},
    ])
    result = conversation(client, chat_id=chat, source='live')['structuredContent']
    assert result['messages'][0] == {'id': 'false_' + chat + '_C', 'content_state': 'clear_chat_coverage_uncertain'}
    assert 'Synthetic excluded anchor' not in str(result)
    assert result['messages'][1]['body'] == 'Synthetic remaining provider observation'
    assert result['clear_chat_coverage']['boundary_unknown'] is (boundary is None)
    if boundary is None:
        assert result['current_state'] == result['messages'][1]['current_state'] == 'clear_chat_coverage_uncertain'
    assert result['mirror_complete'] is False


def test_live_observation_does_not_replace_acquired_edit(app_client):
    app, client = app_client
    service = app.state.service
    service.store.ingest(message(IDENTIFIER, chat=CHAT, timestamp=100, text='Synthetic original'))
    service.store.ingest({'id': 'synthetic-edit', 'event': 'message.edited', 'timestamp': 200000,
                          'payload': {'editedMessageId': IDENTIFIER, 'body': 'Synthetic acquired edit'}})
    provider(service, [{'id': IDENTIFIER, 'timestamp': 100, 'body': 'Synthetic provider edit'}])
    live = conversation(client, source='live')['structuredContent']
    acquired = conversation(client)['structuredContent']
    assert live['messages'][0]['body'] == 'Synthetic acquired edit'
    assert live['messages'][0]['body_source'] == 'acquired_edit'
    assert live['messages'][0]['current_state'] == 'edit_conflict'
    assert live['current_state'] == 'provider_observation'
    assert acquired['messages'][0]['body'] == 'Synthetic acquired edit'
    assert acquired['source'] == 'acquired_archive'


def test_configured_maintenance_diagnostics_ignore_unrelated_legacy_gate(environment, monkeypatch):
    settings, receiver, gateway, _ = environment
    legacy = settings.database.parent / 'legacy-gate'
    configured = settings.database.parent / 'configured-gate'
    legacy.touch()
    monkeypatch.setattr('sally_whatsapp.server.MAINTENANCE_GATE', legacy)
    app = create_app(settings, gateway=gateway, event_transport=receiver,
                     start_worker=False, maintenance_gate=configured)
    service = app.state.service
    assert not service.connection_status()['recovery_diagnostics']['maintenance_active']
    configured.touch()
    diagnostic = service.connection_status()['recovery_diagnostics']
    assert diagnostic['maintenance_active'] and diagnostic['warning_kind'] == 'maintenance'
    legacy.unlink()
    assert service.connection_status()['recovery_diagnostics']['maintenance_active']
    service.diagnostics.close()


def test_cli_passes_resolved_maintenance_gate(environment, monkeypatch):
    from sally_whatsapp import cli, installation, server
    settings, *_ = environment
    gate = settings.database.parent / 'configured-gate'
    monkeypatch.setattr('sys.argv', ['bridge', '--config', 'synthetic', 'serve'])
    monkeypatch.setattr(cli.Settings, 'load', lambda path: settings)
    monkeypatch.setattr(installation, 'mapped', lambda path: str(gate))
    observed = []
    monkeypatch.setattr(server, 'create_app', lambda settings, **kwargs: observed.append(kwargs))
    monkeypatch.setattr(cli.uvicorn, 'run', lambda *args, **kwargs: None)
    cli.main()
    assert observed == [{'maintenance_gate': gate}]


def test_revocation_arriving_during_live_read_wins_over_provider_page(app_client):
    app, client = app_client
    service = app.state.service
    def request(*args, **kwargs):
        service.store.ingest({'id': 'synthetic-concurrent-revoke', 'event': 'message.revoked',
                              'payload': {'revokedMessageId': IDENTIFIER}})
        return [{'id': IDENTIFIER, 'timestamp': 100, 'body': 'Synthetic revoked during read'}]
    service.gateway.request = request
    result = conversation(client, source='live')['structuredContent']
    assert result['messages'] == [{'id': IDENTIFIER, 'content_state': 'revoked'}]


def test_wrong_user_cannot_query_recent_live_messages(app_client, environment):
    app, client = app_client
    requests = provider(app.state.service, [{'id': IDENTIFIER, 'body': 'Synthetic owner content'}])
    client.headers['Authorization'] = 'Bearer ' + environment[3](sub='another-synthetic-owner')
    rpc(client, 'tools/call', {'name': 'read_conversation', 'arguments': {'chat_id': CHAT, 'source': 'live'}},
        expected_status=401)
    assert requests == []
