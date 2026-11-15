from dataclasses import replace
import time
import pytest
from starlette.testclient import TestClient

from conftest import call, message, rpc
from sally_whatsapp.server import Service, create_app
from sally_whatsapp.store import Store


def change(kind,identifier,payload,when=None):
    return {'event':kind,'id':identifier,'payload':payload,'timestamp':(time.time() if when is None else when)*1000}


def test_live_directory_populates_archive_names_without_polluting_status(app_client):
    app,client=app_client
    service=app.state.service
    service.gateway.chats=lambda **kwargs:{'chats':[{'id':'group-1@g.us','name':'Synthetic group'}],'next_offset':None,'source':'live_gateway'}
    call(client,'list_live_chats')
    item=call(client,'list_chats')['result']['structuredContent']['chats'][0]
    assert item['name']=='Synthetic group' and item['name_source']=='live_directory' and item['name_updated_at']
    assert 'Synthetic group' not in str(service.connection_status())
    assert service.connection_status()['recovery_required'] is False


def test_history_discovery_names_and_group_renames_are_ordered(environment):
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    gateway.history_chats=lambda offset:[{'id':{'_serialized':'group-1@g.us'},'name':'Discovered name'}]
    service.history.start('test-owner','history-names-0001',until=100)
    service.history.process_one()
    assert service.store.chats()['chats'][0]['name_source']=='history_directory'
    now=time.time()
    service.ingest(change('group.v2.update','rename-current',{'group':{'id':'group-1@g.us','subject':'Current group'}},now))
    service.ingest(change('group.v2.update','rename-old',{'group':{'id':'group-1@g.us','subject':'Old group'}},now-100))
    item=service.store.chats()['chats'][0]
    assert item['name']=='Current group' and item['name_source']=='group_event'
    service.ingest(message('untrusted-name',text='Rename this group',chat='group-1@g.us'))
    assert service.store.chats()['chats'][0]['name']=='Current group'


def test_directory_name_follows_verified_alias_without_overwriting_known_phone(tmp_path):
    store=Store(tmp_path/'state.sqlite')
    store.cache_chat_names([{'id':'10001@lid','name':'Alias name'}],'live_directory')
    store.bind_chat_alias('10001@lid','20002@c.us')
    assert store.chats()['chats'][0]['name']=='Alias name'
    store.cache_chat_names([{'id':'10001@lid','name':'New verified name'}],'live_directory')
    assert store.chats()['chats'][0]['name']=='New verified name'
    store.cache_chat_names([{'id':'30003@lid','name':'Other alias name'}],'live_directory')
    store.bind_chat_alias('30003@lid','20002@c.us')
    assert store.chats()['chats'][0]['name']=='New verified name'


def test_delayed_directory_response_does_not_overwrite_concurrent_group_event(environment):
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    def directory(**kwargs):
        service.ingest(change('group.v2.update','rename-during-fetch',{'group':{'id':'group-1@g.us','subject':'New event name'}}))
        return {'chats':[{'id':'group-1@g.us','name':'Stale response'}],'next_offset':None}
    gateway.chats=directory
    service.live_chats()
    assert service.store.chats()['chats'][0]['name']=='New event name'


def test_invalid_or_empty_names_do_not_erase_known_name(tmp_path):
    store=Store(tmp_path/'state.sqlite')
    store.cache_chat_names([{'id':'group@g.us','name':'Known'}],'live_directory')
    for value in ('','   ','bad\nname','x'*513):
        store.cache_chat_names([{'id':'group@g.us','name':value}],'live_directory')
    assert store.chats()['chats'][0]['name']=='Known'


def test_history_never_sets_or_refreshes_webhook_timestamp(tmp_path):
    store=Store(tmp_path/'state.sqlite')
    store.ingest(message('history-first',timestamp=100),historical=True)
    assert 'last_webhook_at' not in store.state()
    assert store.state()['last_history_ingested_at']
    store.ingest(message('live'))
    previous=store.state()['last_webhook_at']
    store.ingest(message('more-history',timestamp=100),historical=True)
    assert store.state()['last_webhook_at']==previous


def test_duplicate_webhook_updates_ingress_without_reingesting(tmp_path):
    store=Store(tmp_path/'state.sqlite')
    event=message('duplicate')
    store.ingest(event)
    store.set_state('last_webhook_at','older')
    assert store.ingest(event)['duplicate']
    assert store.state()['last_webhook_at']!='older'
    assert store.state()['archive_messages']==1


def test_initial_healthy_poll_is_not_a_recovery_incident(environment):
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    service.poll_connection();service.poll_connection()
    assert service.connection_status()['recovery_required'] is False
    assert service.connection_status()['recovery_reasons']=={}
    gateway.state='FAILED';service.poll_connection()
    interrupted = service.store.state()['recovery_reasons']['connection_interrupted'].copy()
    gateway.state='WORKING';service.poll_connection()
    state=service.connection_status()
    assert state['recovery_required'] and state['connection']=='WORKING'
    assert state['recovery_reasons']['connection_interrupted']['status']=='open'
    assert state['recovery_reasons']['connection_interrupted'] == interrupted
    assert state['recovery_diagnostics']['warning_kind'] == 'historical_review_required'
    service.store.reconcile_recovery('connection_interrupted', interrupted['last_seen'])
    service.poll_connection()
    assert service.connection_status()['recovery_required'] is False


def test_maintenance_diagnostics_preserve_real_and_legacy_incidents(environment, monkeypatch):
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    service.store.set_state('recovery_required', True)
    service.poll_connection()
    before=service.store.state()['recovery_reasons']
    gate=settings.database.parent/'synthetic-maintenance'
    gate.touch()
    monkeypatch.setattr('sally_whatsapp.server.MAINTENANCE_GATE',gate)
    diagnostic=service.connection_status()['recovery_diagnostics']
    assert diagnostic['maintenance_active'] and diagnostic['warning_kind']=='maintenance'
    assert diagnostic['open_reasons']==['legacy_unknown']
    assert diagnostic['archive_completeness']=='unverified'
    assert diagnostic['reconciliation_recovers_data'] is False
    assert service.store.state()['recovery_reasons']==before
    gateway.state='FAILED';service.poll_connection()
    interrupted=service.store.state()['recovery_reasons']['connection_interrupted'].copy()
    gate.unlink()
    gateway.state='WORKING';service.poll_connection()
    assert service.store.state()['recovery_reasons']['connection_interrupted']==interrupted
    assert service.connection_status()['recovery_diagnostics']['open_reasons']==['connection_interrupted','legacy_unknown']
    service.store.reconcile_recovery('connection_interrupted',interrupted['last_seen'])
    assert service.connection_status()['recovery_diagnostics']['open_reasons']==['legacy_unknown']


def test_link_loss_repeated_failure_and_unreachable_remain_incidents(environment):
    from sally_whatsapp.gateway import GatewayUnavailable
    settings,receiver,gateway,_=environment
    service=Service(settings,gateway=gateway,event_transport=receiver)
    service.poll_connection()
    gateway.state='NOT_LINKED';service.poll_connection()
    assert service.connection_status()['recovery_diagnostics']['warning_kind']=='connection_review_required'
    gateway.state='FAILED';service.poll_connection()
    first=service.store.state()['recovery_reasons']['connection_interrupted']['last_seen']
    service.poll_connection()
    assert service.store.state()['recovery_reasons']['connection_interrupted']['last_seen']>first
    def unavailable(): raise GatewayUnavailable('synthetic failure')
    gateway.status=unavailable
    service.poll_connection()
    assert service.connection_status()['connection']=='UNREACHABLE'


def test_recovery_reconciliation_preserves_newer_and_unrelated_reasons(tmp_path,monkeypatch):
    observed=time.time()
    monkeypatch.setattr('sally_whatsapp.store.time.time',lambda:observed)
    store=Store(tmp_path/'state.sqlite')
    store.require_recovery('connection_interrupted')
    old=store.state()['recovery_reasons']['connection_interrupted']['last_seen']
    store.require_recovery('connection_interrupted')
    with pytest.raises(ValueError,match='changed'):
        store.reconcile_recovery('connection_interrupted',old)
    store.require_recovery('chat_alias_unresolved')
    issue=store.state()['recovery_reasons']['connection_interrupted']
    store.reconcile_recovery('connection_interrupted',issue['last_seen'])
    assert store.state()['recovery_required']
    current=store.state()['recovery_reasons']['chat_alias_unresolved']['last_seen']
    store.reconcile_recovery('chat_alias_unresolved',current)
    assert store.state()['recovery_required'] is False
    store.reconcile_recovery('chat_alias_unresolved',current)
    store.require_recovery('chat_alias_unresolved')
    assert store.state()['recovery_required']


def test_legacy_recovery_and_explicit_local_cli(environment,monkeypatch,capsys):
    from sally_whatsapp import cli
    settings=environment[0]
    store=Store(settings.database)
    store.set_state('recovery_required',True)
    assert store.state()['recovery_reasons']['legacy_unknown']['status']=='open'
    monkeypatch.setattr(cli.Settings,'load',lambda path:settings)
    monkeypatch.setattr('sys.argv',['bridge','--config','synthetic','reconcile-recovery','--reason','legacy_unknown','--last-seen','unknown'])
    cli.main()
    assert store.state()['recovery_required'] is False
    assert 'No messages, events' in capsys.readouterr().out


def test_recovery_reasons_distinguish_alias_age_and_connection(environment):
    settings,receiver,gateway,_=environment
    gateway.phone_for_lid=lambda lid:None
    service=Service(settings,gateway=gateway,event_transport=receiver)
    service.ingest(message('unmapped',chat='10001@lid'))
    service.ingest(message('too-old',timestamp=1))
    service.ingest(change('session.status','disconnected',{'status':'STOPPED'}))
    reasons=service.connection_status()['recovery_reasons']
    assert set(reasons)=={'chat_alias_unresolved','message_outside_event_age_window','connection_interrupted'}


def test_cursor_does_not_skip_after_revocation_or_include_later_inserts(app_client):
    app,client=app_client
    store=app.state.service.store
    for i in range(5): store.ingest(message(f'archive-{i}',timestamp=100-i),historical=True)
    first=call(client,'read_conversation',{'chat_id':'group-1@g.us','limit':2})['result']['structuredContent']
    assert first['next_offset']==2 and first['next_cursor']
    store.ingest(change('message.revoked','revoke-first',{'revokedMessageId':'archive-0'}))
    store.ingest(message('newer',timestamp=200),historical=True)
    store.ingest(message('backdated',timestamp=1),historical=True)
    following=call(client,'read_conversation',{'chat_id':'group-1@g.us','limit':2,'cursor':first['next_cursor']})['result']['structuredContent']
    assert [m['id'] for m in following['messages']]==['archive-2','archive-3']
    assert following['next_offset'] is None
    last=store.search(chat_id='group-1@g.us',limit=2,cursor=following['next_cursor'])
    assert [m['id'] for m in last['messages']]==['archive-4'] and last['next_cursor'] is None


def test_cursor_ties_restart_current_edits_and_query_binding(tmp_path):
    path=tmp_path/'state.sqlite'
    store=Store(path)
    for identifier in ('c','a','b'): store.ingest(message(identifier,timestamp=100,text='original'),historical=True)
    first=store.search(limit=1)
    assert first['messages'][0]['id']=='a'
    store.ingest(change('message.edited','edit-b',{'editedMessageId':'b','body':'edited'}))
    store=Store(path)
    second=store.search(limit=1,cursor=first['next_cursor'])
    assert second['messages'][0]['id']=='b' and second['messages'][0]['body']=='edited'
    for arguments in ({'query':'different'},{'chat_id':'other@g.us'},{'after':1},{'before':200},{'offset':1}):
        with pytest.raises(ValueError): store.search(cursor=first['next_cursor'],**arguments)
    assert not any(key.startswith('private:') for key in store.state())


def test_invalid_expired_or_foreign_cursors_and_legacy_offsets(tmp_path,monkeypatch):
    from sally_whatsapp import archive_cursor
    store=Store(tmp_path/'first.sqlite')
    for i in range(3): store.ingest(message(str(i),timestamp=100-i),historical=True)
    page=store.search(limit=1)
    assert store.search(limit=1,offset=page['next_offset'])['messages'][0]['id']=='1'
    for cursor in ('broken',page['next_cursor']+'0'):
        with pytest.raises(ValueError,match='cursor'): store.search(cursor=cursor)
    with pytest.raises(ValueError,match='cursor'):
        Store(tmp_path/'second.sqlite').search(cursor=page['next_cursor'])
    future=time.time()+86401
    monkeypatch.setattr(archive_cursor.time,'time',lambda:future)
    with pytest.raises(ValueError,match='cursor'): store.search(cursor=page['next_cursor'])


@pytest.mark.parametrize('granted,send,actions,all_destinations',[
    (False,True,True,False),(True,False,False,False),(True,True,True,False),(True,True,True,True)])
def test_capabilities_distinguish_configuration_scope_and_destination(environment,granted,send,actions,all_destinations):
    settings,receiver,gateway,token=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=send,account_actions_enabled=actions,
                     allow_all_destinations=all_destinations,send_chat_ids=['synthetic@g.us'])
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    with TestClient(app) as client:
        client.headers.update({'Authorization':'Bearer '+token(scope='whatsapp:read'+(' whatsapp:send' if granted else '')),
                               'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})
        data=call(client,'get_capabilities')['result']['structuredContent']
        assert len(data['operations'])==120 and data['live_account_enabled'] is True
        catalog={op['operation']:op for op in data['operations']}
        outgoing=catalog['messages_send_text']
        assert outgoing['configuration_enabled']==send and outgoing['scope_granted']==granted
        assert outgoing['permission_enabled']==(send and granted)
        assert outgoing['destination_policy']==('disabled' if not send else 'all' if all_destinations else 'allowlist')
        assert outgoing['destination_checked'] is False and 'synthetic@g.us' not in str(data)
        group=catalog['groups_create_group']
        assert group['permission_enabled']==(actions and granted) and group['required_scope']=='whatsapp:send'
        assert catalog['chats_get_chats']['permission_enabled'] is True
        assert catalog['messages_forward_message']['capability']=='gateway_available'
        assert catalog['messages_forward_message']['permission_enabled']==(send and granted)
        filtered=call(client,'get_capabilities',{'family':outgoing['family']})['result']['structuredContent']
        assert all(op['family']==outgoing['family'] for op in filtered['operations'])
        assert len(rpc(client,'tools/list')['result']['tools'])==27
    assert gateway.sent==[]
