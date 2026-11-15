"""Public effects of reads, exercised here with synthetic local state."""
import hashlib
import json
import time
from types import SimpleNamespace

from conftest import call, message, rpc
from sally_whatsapp import server


def advertised(client, name, expected):
    tool = next(item for item in rpc(client, 'tools/list')['result']['tools'] if item['name'] == name)
    assert tool['annotations'] == dict(zip(
        ('readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'), expected))
    scopes = [{'type': 'oauth2', 'scopes': ['whatsapp:read']}]
    assert tool['securitySchemes'] == scopes
    assert tool['_meta']['securitySchemes'] == scopes
    return tool


def read_client(environment, app_client):
    app, client = app_client
    client.headers['Authorization'] = 'Bearer ' + environment[3](scope='whatsapp:read')
    return app.state.service, client


def no_outbound_actions(environment):
    assert environment[2].sent == []
    assert environment[1].requests == []


def test_profile_identity_and_declared_profile_contract_are_preserved(environment, app_client):
    service, client = read_client(environment, app_client)
    key = 'profile_id:' + hashlib.sha256(b'test-owner').hexdigest()
    with service.store.db() as db:
        prepared = db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()[0]
    first = call(client, 'get_profile')['result']['structuredContent']
    assert first['id'] == json.loads(prepared)
    with service.store.db() as db:
        assert db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()[0] == prepared
    assert call(client, 'get_profile')['result']['structuredContent'] == first
    no_outbound_actions(environment)
    # Startup prepared the identity before this read-only MCP request.
    tool = advertised(client, 'get_profile', (True, False, True, False))
    assert tool['_meta']['openai/profile'] is True
    assert set(tool['outputSchema']['required']) == {'id', 'nickname'}


def test_live_directory_contract_accounts_for_public_cache_updates(environment, app_client, monkeypatch):
    service, client = read_client(environment, app_client)
    chat = 'synthetic-directory@g.us'
    service.store.cache_chat_names([{'id': chat, 'name': 'Previous name'}], 'live_directory', observed_at=100)
    service.gateway.chats = lambda **kwargs: {'chats': [{'id': chat, 'name': 'Observed name'}], 'next_offset': None}
    observation = [200]
    # Replace only server's clock reference; token verification keeps real time.
    monkeypatch.setattr(server, 'time', SimpleNamespace(time=lambda: observation[0], monotonic=time.monotonic))
    call(client, 'list_live_chats')
    first = call(client, 'list_chats')['result']['structuredContent']['chats'][0]
    assert first['name'] == 'Observed name' and first['name_source'] == 'live_directory'
    observation[0] = 300
    call(client, 'list_live_chats')
    second = call(client, 'list_chats')['result']['structuredContent']['chats'][0]
    assert second['name'] == first['name']
    assert second['name_updated_at'] > first['name_updated_at']
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM chats WHERE id=?', (chat,)).fetchone()[0] == 1
        assert json.loads(db.execute('SELECT value FROM state WHERE key=?', ('chat_name:' + chat,)).fetchone()[0])['updated_epoch'] == 300
    no_outbound_actions(environment)
    advertised(client, 'list_live_chats', (False, True, False, False))


def test_transfer_status_contract_accounts_for_existing_revocation(environment, app_client):
    service, client = read_client(environment, app_client)
    source_id = 'synthetic-revoked-source'
    envelope = message(source_id)
    service.store.ingest(envelope)
    transfer = service.media.enqueue('test-owner', {
        'kind': 'gateway', 'message_id': source_id, 'chat_id': 'group-1@g.us',
        'media': {'url': 'https://synthetic.invalid/file'}}, 'synthetic.txt', 'text/plain')['id']
    path = service.media.path(transfer)
    path.write_bytes(b'synthetic cached content')
    # An old row whose independently recorded revocation still needs applying.
    with service.store.db() as db:
        db.execute('INSERT INTO message_mutations (message_id,kind,body,event_epoch) VALUES(?,?,NULL,?)',
                   (source_id, 'revoked', time.time()))
        assert db.execute('SELECT state FROM media_jobs WHERE id=?', (transfer,)).fetchone()[0] == 'queued'
    first = call(client, 'get_transfer_status', {'transfer_id': transfer})['result']['structuredContent']
    assert first['state'] == 'cancelled' and first['error'] == service.media.REVOKED
    assert {key: first[key] for key in ('filename', 'mimetype', 'size', 'sha256')} == {
        'filename': '', 'mimetype': '', 'size': None, 'sha256': None}
    assert 'download_url' not in first and not path.exists()
    with service.store.db() as db:
        before_repeat = dict(db.execute('SELECT * FROM media_jobs WHERE id=?', (transfer,)).fetchone())
        assert before_repeat['source'] == b'' and before_repeat['source_message_id'] == source_id
    second = call(client, 'get_transfer_status', {'transfer_id': transfer})['result']['structuredContent']
    first_cache, second_cache = first.pop('cache'), second.pop('cache')
    # Repeated reads preserve effects and transfer data; the quota observation
    # gets a fresh timestamp without reserving bytes or changing the ledger.
    assert second_cache.pop('observed_at') >= first_cache.pop('observed_at')
    assert second_cache == first_cache and second == first
    with service.store.db() as db:
        assert dict(db.execute('SELECT * FROM media_jobs WHERE id=?', (transfer,)).fetchone()) == before_repeat
        assert db.execute('SELECT count(*) FROM media_jobs').fetchone()[0] == 1
    no_outbound_actions(environment)
    # This archive-backed case is local, but the same tool also revalidates a
    # live source through the provider before returning a signed download URL.
    advertised(client, 'get_transfer_status', (False, True, True, True))
