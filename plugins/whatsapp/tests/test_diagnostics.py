import json
import time
from dataclasses import replace

from starlette.testclient import TestClient
from conftest import call
from sally_whatsapp.diagnostics import Diagnostics
from sally_whatsapp.server import create_app


def records(settings):
    directory=settings.database.parent/'diagnostics'
    return [json.loads(line) for path in directory.glob('events.jsonl*') for line in path.read_text().splitlines()]


def test_sensitive_arguments_tokens_and_urls_never_enter_diagnostics(app_client,environment):
    app,client=app_client
    settings,_,_,token=environment
    secret='private-message-393335551234'
    response=call(client,'search_messages',{'query':secret})
    assert not response['result'].get('isError',False)
    call(client,'send_text',{'chat_id':'393335551234@c.us','text':secret,'idempotency_key':'sensitive-key-000001'})
    client.get('/files/secret-file-grant?token=secret-query')
    client.get('/connect/callback?code=secret-oauth-code')
    client.headers['Authorization']='Bearer '+token(exp=int(time.time())-10)
    assert client.post('/mcp').status_code==401
    text=json.dumps(records(settings))
    for forbidden in (secret,'393335551234','sensitive-key-000001','secret-file-grant','secret-query','secret-oauth-code',client.headers['Authorization']):
        assert forbidden not in text
    assert 'AUTH_TOKEN' in text and 'ExpiredSignatureError' in text


def test_internal_tool_failure_returns_matching_reference_without_exception_text(app_client,environment):
    app,client=app_client
    settings,_,gateway,_=environment
    def broken(*args,**kwargs): raise RuntimeError('password=must-not-appear')
    gateway.chats=broken
    result=call(client,'list_live_chats')['result']
    assert result['isError'] is True
    identifier=result['_meta']['whatsapp/request_id']
    failed=[r for r in records(settings) if r['event']=='tool.failed'][-1]
    assert failed['request_id']==identifier
    assert failed['exception']=='RuntimeError' and failed['error_code']=='INTERNAL_TOOL_ERROR'
    assert 'must-not-appear' not in json.dumps(result)+json.dumps(records(settings))


def test_rotation_bounds_storage_and_drops_unknown_fields(environment):
    settings,*_=environment
    diagnostic=Diagnostics(replace(settings,diagnostics_max_bytes=65536,diagnostics_backups=1))
    for _ in range(1500):
        diagnostic.emit('test.event',tool='get_profile',password='never-log-this',url='https://secret',body='private')
    diagnostic.close()
    files=list(diagnostic.directory.glob('events.jsonl*'))
    assert len(files)==2 and sum(p.stat().st_size for p in files)<131072
    text=''.join(p.read_text() for p in files)
    assert 'never-log-this' not in text and 'secret' not in text and 'private' not in text


def test_http_failure_has_safe_json_and_correlation(environment):
    settings,receiver,gateway,_=environment
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    def broken(*args,**kwargs): raise RuntimeError('https://secret-download/?key=never-log')
    app.state.service.media.resolve=broken
    with TestClient(app) as client:
        response=client.get('/files/secret-grant')
    assert response.status_code==500
    assert response.json()['request_id']==response.headers['x-request-id']
    assert 'never-log' not in json.dumps(records(settings))


def test_each_instance_keeps_its_own_log_files(environment,tmp_path):
    settings,*_=environment
    one=Diagnostics(settings)
    two=Diagnostics(replace(settings,database=tmp_path/'separate-user'/'archive.sqlite'))
    one.emit('first.account')
    two.emit('second.account')
    one.close();two.close()
    assert 'second.account' not in (one.directory/'events.jsonl').read_text()
    assert 'first.account' not in (two.directory/'events.jsonl').read_text()


def test_validly_signed_invalid_webhook_has_safe_reason(app_client,environment):
    import hmac
    app,client=app_client
    settings,*_=environment
    raw=json.dumps({'event':'message.any','session':'default','payload':{
        'id':'private-id','fromMe':False,'from':'393335551234@c.us','body':'private-content','timestamp':'invalid'}}).encode()
    signature=hmac.digest(settings.webhook_secret_file.read_bytes(),raw,'sha512').hex()
    response=client.post('/webhooks/waha',content=raw,headers={'x-webhook-hmac-algorithm':'sha512','x-webhook-hmac':signature})
    assert response.status_code==400
    record=[r for r in records(settings) if r['event']=='webhook.rejected'][-1]
    assert record['source_event']=='message.any' and record['error_code']=='MESSAGE_CHAT_TIME'
    assert 'private-content' not in json.dumps(records(settings))


def test_administrative_report_normalizes_legacy_without_database_mutation(environment,monkeypatch):
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace
    from sally_whatsapp.store import Store
    settings,*_=environment
    store=Store(settings.database)
    store.set_state('recovery_required',True)
    before=settings.database.read_bytes()
    spec=importlib.util.spec_from_file_location('administrative_diagnostics',Path(__file__).parents[1]/'scripts/diagnostics.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    monkeypatch.setattr(module.Settings,'load',lambda path:settings)
    monkeypatch.setattr(module.subprocess,'run',lambda *args,**kwargs:SimpleNamespace(stdout='active'))
    class Client:
        def __init__(self,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def get(self,url,**kwargs):
            value={'version':'synthetic','process':'running'} if url.endswith('/healthz') else {'status':'WORKING'}
            return SimpleNamespace(status_code=200,is_success=True,json=lambda:value)
    monkeypatch.setattr(module.httpx,'Client',Client)
    settings.waha_key_file.write_text('synthetic-test-key')
    instance=SimpleNamespace(config_dir=settings.database.parent,slug='synthetic',base='synthetic',wrapper=Path('synthetic-wrapper'),bridge_port=8820,gateway_port=8821)
    report=module.inspect(instance,24,1)
    assert report['media_cache']['capacity_bytes']==settings.media_cache_bytes
    assert report['media_cache']['used_bytes']==0
    assert report['media_cache']['effective_limit_bytes']==settings.max_attachment_bytes
    assert report['media_cache']['accounting']=='ready_unexpired'
    assert report['disk_free_bytes']>=0
    assert report['runtime']['recovery_reasons']==store.state()['recovery_reasons']
    assert report['runtime']['recovery_reasons']['legacy_unknown']['last_seen'] is None
    assert settings.database.read_bytes()==before
