"""Provider and acquired receipt observations stay separate and tenant-bound."""
import copy
import json

import pytest

from sally_whatsapp.linked_state_reads import project_live_read
from sally_whatsapp.store import Store
from test_delivery_receipts import PROVIDER, reserve, receipt


def project(store, *, ack=1, identifier=PROVIDER, chat='fixture@c.us'):
    value = {'id':identifier, 'ack':ack, 'fromMe':True, 'to':chat, 'body':'synthetic-content'}
    original = copy.deepcopy(value)
    result = project_live_read(store, 'chats_get_chat_message',
                             {'path':{'chatId':chat,'messageId':identifier}}, value, observed_at=2000)
    assert value == original
    return result['result']


def test_read_without_observed_device_does_not_rewrite_cache_or_fill_missing_level(tmp_path):
    store = Store(tmp_path/'one.db'); reserve(store); receipt(store, 3)
    value = project(store)
    assert value['ack'] == 1
    evidence = value['ack_provenance']
    assert evidence['enum'] == 'WAHA_WAMessageAck' and evidence['ack_name'] == 'SERVER'
    assert evidence['comparison'] == 'provider_cache_behind_acquired_receipt'
    assert evidence['phone_current_state'] == evidence['observed_at_source'] == 'unknown'
    assert set(evidence['acquired_receipts']['evidence']) == {'read'}
    assert project(store, ack=3)['ack_provenance']['comparison'] == 'consistent_observations'
    assert store.send_status('synthetic-receipt-request')['state'] == 'submitted'


def test_waha_device_two_is_not_gows_server_two(tmp_path):
    store = Store(tmp_path/'one.db')
    assert project(store, ack=2)['ack_provenance']['ack_name'] == 'DEVICE'


@pytest.mark.parametrize('ack', [True, '3', None, 99])
def test_invalid_ack_never_becomes_receipt_evidence(tmp_path, ack):
    store = Store(tmp_path/'one.db')
    value = project(store, ack=ack)['ack_provenance']
    assert value['ack'] is None and value['comparison'] == 'not_compared'


def test_identical_keys_in_other_instance_or_other_chat_do_not_supply_evidence(tmp_path):
    one, two = Store(tmp_path/'one.db'), Store(tmp_path/'two.db')
    reserve(one); reserve(two); receipt(one,3)
    assert project(one)['ack_provenance']['comparison'] == 'provider_cache_behind_acquired_receipt'
    assert project(two)['ack_provenance']['acquired_receipts']['status'] == 'not_observed'
    assert project(one,chat='different@c.us') == {'id':PROVIDER, 'content_state':'unverified_reference'}
    assert one.message_delivery_evidence(PROVIDER, 'different@c.us')['status'] == 'not_correlated'


def test_ambiguous_action_and_revocation_withhold_evidence(tmp_path):
    store = Store(tmp_path/'one.db'); reserve(store); receipt(store,3)
    reserve(store, request='second-action-same-id')
    assert project(store)['ack_provenance']['acquired_receipts']['status'] == 'ambiguous'
    store.ingest({'id':'synthetic-revoke','event':'message.revoked','payload':{'revokedMessageId':PROVIDER}})
    result = project(store)
    assert result == {'id':PROVIDER, 'content_state':'revoked'}
    assert 'synthetic-content' not in json.dumps(result)


@pytest.mark.parametrize('operation', ['messages_set_reaction', 'chats_edit_message', 'messages_set_star'])
def test_non_message_action_returning_original_id_does_not_hide_cached_receipt_comparison(tmp_path, operation):
    store = Store(tmp_path/'one.db'); reserve(store); receipt(store,3)
    store.queue_action('synthetic-non-message-action','test-owner',operation,{'body':{}})
    store.finish_send('synthetic-non-message-action','submitted',provider_id=PROVIDER,result={'id':PROVIDER})
    evidence = project(store)['ack_provenance']
    assert evidence['comparison'] == 'provider_cache_behind_acquired_receipt'
    assert set(evidence['acquired_receipts']['evidence']) == {'read'}
