"""Public invocation guidance must not echo private values or unknown field names."""
import json

import pytest

from conftest import call


@pytest.mark.parametrize('tool,extra',[
    ('send_text',{'chat_id':'synthetic@g.us','text':'private synthetic content'}),
    ('write_whatsapp',{'operation':'messages_send_text',
                       'arguments':{'body':{'chatId':'synthetic@g.us','text':'private synthetic content'}}}),
    ('get_send_status',{}),
])
def test_short_key_explains_published_constraints_without_echoing_input(app_client,tool,extra):
    app,client=app_client
    value=call(client,tool,{**extra,'idempotency_key':'short-private'})['result']
    assert value['isError'] is True
    detail=value['structuredContent']
    assert detail['error_code']=='INVALID_ARGUMENT'
    constraint=detail['field_constraints']['idempotency_key']
    assert constraint['minLength']==16
    assert constraint['maxLength']==128
    encoded=json.dumps(value)
    assert 'short-private' not in encoded
    assert 'private synthetic content' not in encoded
    with app.state.service.store.db() as db:
        assert db.execute('SELECT count(*) FROM sends').fetchone()[0]==0


def test_unknown_argument_key_is_not_reflected(app_client):
    _,client=app_client
    value=call(client,'get_profile',{'private-extra-field':{'secret':'private-extra-value'}})['result']
    assert value['isError'] is True
    assert value['structuredContent']['field_constraints']=={}
    assert 'private-extra' not in json.dumps(value)


def test_unknown_operation_is_not_reflected(app_client):
    _,client=app_client
    value=call(client,'get_operation_schema',{'operation':'private-invalid-operation'})['result']
    assert value['isError'] is True
    assert 'operation' in value['structuredContent']['field_constraints']
    assert 'private-invalid-operation' not in json.dumps(value)
