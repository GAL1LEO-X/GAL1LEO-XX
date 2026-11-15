"""OAuth replacement grants and actual tool effects, using only isolated fakes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace

import pytest
from starlette.testclient import TestClient

from conftest import FakeGateway, Receiver, call, message, rpc, subscribe
from sally_whatsapp.auth import JWTVerifier
from sally_whatsapp.config import MCP_SCOPES
from sally_whatsapp.server import create_app


def grant(token, scopes, array=False, **changes):
    return (token(_omit=('scope',), scp=scopes, **changes) if array
            else token(scope=' '.join(scopes), **changes))


def challenged(value):
    assert value['isError'] is True
    return value['_meta']['mcp/www_authenticate'][0].rsplit('scope="', 1)[1].split('"', 1)[0].split()


def headers(token):
    return {'Authorization':'Bearer '+token, 'Accept':'application/json, text/event-stream',
            'MCP-Protocol-Version':'2026-07-28'}


@pytest.mark.parametrize('array', [False, True])
@pytest.mark.parametrize('has_events', [False, True])
@pytest.mark.parametrize('name', ['send_text', 'write_whatsapp', 'send_media'])
def test_exact_send_replacement_preserves_transport_and_events(environment, app_client, array, has_events, name):
    app, client = app_client
    service = app.state.service
    service.settings = replace(environment[0], live_account_enabled=True, send_enabled=True,
                               send_chat_ids=['group-1@g.us'])
    arguments = {'idempotency_key':'synthetic-send-upgrade-0001'}
    if name == 'send_text':
        arguments.update(chat_id='group-1@g.us', text='synthetic')
    else:
        arguments.update(operation='messages_send_text', arguments={'body':{'chatId':'group-1@g.us','text':'synthetic'}})
        if name == 'send_media':
            job = service.media.enqueue('test-owner', {'kind':'gateway','media':{'url':'synthetic'}},
                                        'synthetic.txt','text/plain')
            assert service.media.process_one()
            arguments.update(operation='messages_send_file', arguments={'body':{'chatId':'group-1@g.us'}},
                             transfer_id=job['id'])
    original = ['whatsapp:read'] + (['whatsapp:events'] if has_events else [])
    client.headers['Authorization'] = 'Bearer '+grant(environment[3], original, array)
    scopes = challenged(call(client, name, arguments)['result'])
    assert scopes == ['whatsapp:read','whatsapp:send'] + (['whatsapp:events'] if has_events else [])
    assert not environment[2].sent and not environment[1].requests
    # The old token remains unauthorized; the challenge itself grants nothing.
    assert challenged(call(client, name, arguments)['result']) == scopes
    client.headers['Authorization'] = 'Bearer '+grant(environment[3], scopes, array)
    assert call(client, 'get_profile')['result']['structuredContent']['id']
    result = call(client, name, arguments)['result']
    assert not result.get('isError')
    assert result['structuredContent']['state'] == ('submitted' if name == 'send_text' else 'queued')
    event = call(client, 'check_event_authorization')['result']
    if has_events:
        assert event['structuredContent']['authorized'] is True
    else:
        assert challenged(event) == ['whatsapp:read','whatsapp:events','whatsapp:send']
    assert environment[1].requests == []


@pytest.mark.parametrize('array', [False, True])
@pytest.mark.parametrize('allowed', [
    ['whatsapp:read'], ['whatsapp:read','whatsapp:events'], ['whatsapp:read','whatsapp:send'],
])
def test_resource_policy_filters_grants_and_never_challenges_disabled_scopes(environment, array, allowed):
    settings, receiver, gateway, token = environment
    settings = replace(settings, oauth_allowed_scopes=allowed)
    signed = grant(token, list(MCP_SCOPES)+['openid','email','offline_access','custom:unrelated','whatsapp:link'], array)
    verified = JWTVerifier(settings)._verify(signed)
    assert verified is not None
    assert set(verified.scopes).intersection(MCP_SCOPES) == set(allowed)
    # Pairing/OIDC are not reinterpreted as resource scopes by the shared verifier.
    assert 'whatsapp:link' in verified.scopes
    app = create_app(settings, gateway=gateway, event_transport=receiver, start_worker=False)
    with TestClient(app) as client:
        client.headers.update(headers(signed))
        assert client.get('/.well-known/oauth-protected-resource').json()['scopes_supported'] == allowed
        for name, scope in [('send_text','whatsapp:send'), ('check_event_authorization','whatsapp:events')]:
            if scope in allowed:
                continue
            result = call(client, name)['result']
            assert result['isError'] is True
            assert result['structuredContent']['error_code'] == 'OAUTH_SCOPE_DISABLED'
            assert 'mcp/www_authenticate' not in result.get('_meta', {})
        if 'whatsapp:events' not in allowed:
            assert subscribe(client)['error']['code'] == -32001
        # If send is allowed, ask for it without reflecting a removed events grant.
        if 'whatsapp:send' in allowed:
            client.headers['Authorization'] = 'Bearer '+grant(token,['whatsapp:read','whatsapp:events'],array)
            assert challenged(call(client,'send_text')['result']) == ['whatsapp:read','whatsapp:send']
    assert gateway.sent == [] and receiver.requests == []


@pytest.mark.parametrize('policy', [None, 'whatsapp:read', [], ['whatsapp:send'],
    ['whatsapp:read', 'whatsapp:read'], ['whatsapp:read', 'whatsapp:link'],
    ['whatsapp:read', 'custom:scope'], ['whatsapp:read', 1]])
def test_invalid_resource_policy_fails_before_serving(environment, policy):
    with pytest.raises(ValueError, match='oauth_allowed_scopes'):
        replace(environment[0], oauth_allowed_scopes=policy)


def test_challenges_and_static_requirements_are_request_local_across_tenants(environment, tmp_path):
    settings, _, _, token = environment
    clients = []
    with ExitStack() as stack:
        for index in range(2):
            folder = tmp_path/str(index)
            folder.mkdir()
            cfg = replace(settings, database=folder/'archive.sqlite', owner_subject=f'owner-{index}',
                          public_url=f'https://tenant-{index}.example', oauth_client_ids=[f'client-{index}'],
                          oauth_allowed_scopes=list(MCP_SCOPES) if index == 0 else ['whatsapp:read','whatsapp:send'])
            app = create_app(cfg, gateway=FakeGateway(), event_transport=Receiver(), start_worker=False)
            client = stack.enter_context(TestClient(app))
            clients.append((client, cfg))
        def request(index):
            client, cfg = clients[index]
            client.headers.update(headers(token(aud=cfg.public_url, sub=cfg.owner_subject,
                                                azp=cfg.oauth_client_ids[0], scope='whatsapp:read whatsapp:events')))
            expected = ['whatsapp:read','whatsapp:send'] + (['whatsapp:events'] if index == 0 else [])
            for _ in range(8):
                assert challenged(call(client,'send_text')['result']) == expected
                tools = rpc(client,'tools/list')['result']['tools']
                for item in tools:
                    if item['name'] in ('send_text','write_whatsapp','send_media'):
                        assert item['securitySchemes'] == [{'type':'oauth2','scopes':['whatsapp:read','whatsapp:send']}]
                        assert item['_meta']['securitySchemes'] == item['securitySchemes']
            # A valid signature does not permit crossing owner/client/audience.
            other = clients[1-index][1]
            client.headers['Authorization'] = 'Bearer '+token(aud=other.public_url, sub=other.owner_subject,
                                                              azp=other.oauth_client_ids[0])
            rpc(client,'tools/list',expected_status=401)
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(request, range(2)))


def test_all_tool_annotations_describe_effects_and_leave_oauth_independent(app_client):
    _, client = app_client
    tools = {tool['name']:tool for tool in rpc(client,'tools/list')['result']['tools']}
    local_reads = {'get_profile','connection_status','check_event_authorization','list_chats','search_messages',
        'read_conversation','get_message','get_send_status','get_capabilities','get_operation_schema',
        'get_transfer_status','get_history_sync','list_account_events','get_account_event',
        'transcribe_audio','get_transcription'}
    external_reads = {'list_live_chats','list_contacts','read_whatsapp'}
    transfers = {'get_attachment','prepare_file'}
    keyed_actions = {'send_text','write_whatsapp','send_media','start_history_sync','control_history_sync'}
    assert set(tools) == local_reads | external_reads | transfers | keyed_actions | {'sync_chat'}
    assert len(tools) == 27
    local_effects = {
        'read_conversation': (True, False, True, True),
        'list_live_chats': (False, True, False, False),
        'get_transfer_status': (False, True, True, True),
        'transcribe_audio': (False, True, False, True),
        'get_transcription': (False, True, True, True),
    }
    for name, tool in tools.items():
        expected = {
            'readOnlyHint':name in local_reads | external_reads,
            'destructiveHint':name in {'write_whatsapp','send_media','control_history_sync'},
            'idempotentHint':name not in transfers | {'sync_chat'},
            'openWorldHint':name not in local_reads,
        }
        if name in local_effects:
            expected = dict(zip(('readOnlyHint','destructiveHint','idempotentHint','openWorldHint'), local_effects[name]))
        assert tool['annotations'] == expected
        if name in transfers:
            assert tool['securitySchemes'] == [{'type':'oauth2','scopes':['whatsapp:read']}]


@pytest.mark.parametrize('name', ['prepare_file','get_attachment'])
@pytest.mark.parametrize('terminal', ['failed','expired'])
def test_transfer_effects_match_non_readonly_conditional_dedup(environment, app_client, name, terminal):
    app, client = app_client
    client.headers['Authorization'] = 'Bearer '+environment[3](scope='whatsapp:read')
    store = app.state.service.store
    envelope = message('synthetic-file-message')
    envelope['payload'].update(hasMedia=True, media={'url':'synthetic','filename':'fixture.txt'})
    store.ingest(envelope)
    args = ({'file':{'file_id':'synthetic-file','download_url':'https://fixture.example/file','file_name':'fixture.txt'}}
            if name == 'prepare_file' else {'message_id':'synthetic-file-message'})
    def count():
        with store.db() as db:
            return db.execute('SELECT count(*) FROM media_jobs').fetchone()[0]
    before = count()
    first = call(client,name,args)['result']['structuredContent']
    assert first['state'] == 'queued' and count() == before+1
    assert call(client,name,args)['result']['structuredContent']['id'] == first['id']
    with store.db() as db:
        db.execute('UPDATE media_jobs SET state=? WHERE id=?',(terminal,first['id']))
    second = call(client,name,args)['result']['structuredContent']
    assert second['id'] != first['id'] and count() == before+2
    assert environment[2].sent == [] and environment[1].requests == []
