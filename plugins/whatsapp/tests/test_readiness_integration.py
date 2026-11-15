"""Real ASGI readiness connected to the real release health and transaction gates.

HTTP is routed in memory; gateway identities/systemd and the existing transaction
filesystem fixture are synthetic. No hand-written readiness payload is accepted.
"""
import asyncio
from contextlib import contextmanager,ExitStack
from dataclasses import replace
import io
import json
from threading import Event
import time
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlsplit

import pytest
from starlette.testclient import TestClient

from conftest import FakeGateway,Receiver,message
from test_release_transaction import sandbox as release_sandbox
import github_release as release
from github_release_common import ReleaseError
from release_runtime import Maintenance
import release_transaction as transaction
from sally_whatsapp import __version__
from sally_whatsapp.server import create_app
from sally_whatsapp.state_continuity import register_external_identity
from sally_whatsapp.store import Store,SCHEMA


def runtime_configuration(environment,tmp_path,slug,port,*,database=None,registered=False):
    root=tmp_path/slug;root.mkdir(exist_ok=True)
    settings=replace(environment[0],database=database or root/'archive.sqlite',
                     public_url=f'https://{slug}.example.invalid',listen_port=port,
                     owner_subject='owner-'+slug,diagnostics_enabled=False,
                     state_identity_file=root/'technical-state.json' if registered else None)
    config=root/'config.toml'
    values={'database':str(settings.database),'owner_subject':settings.owner_subject,
            'public_url':settings.public_url,'issuer':settings.issuer,'session':settings.session}
    if settings.state_identity_file is not None:
        values['state_identity_file']=str(settings.state_identity_file)
    config.write_text('[bridge]\n'+'\n'.join(key+' = '+json.dumps(value) for key,value in values.items())+'\n')
    (root/'waha.key').write_text('synthetic-readiness-gateway-key')
    return settings,config


@contextmanager
def runtime(environment,tmp_path,slug,port,gate,*,database=None,configure=None,registered=False):
    settings,config=runtime_configuration(environment,tmp_path,slug,port,database=database,registered=registered)
    gateway=FakeGateway();receiver=Receiver();activation=asyncio.Event()
    if not settings.database.exists():
        Store(settings.database, migrate_schema=False)  # Explicit installation, never implicit recovery.
    app=create_app(settings,gateway=gateway,event_transport=receiver,
                   recover_inflight=False,activation_event=activation)
    if configure: configure(app.state.service)
    instance={'slug':slug,'base':slug,'unit':slug+'.service','port':port,'config':str(config)}
    with TestClient(Maintenance(app,activation,gate=gate)) as client:
        yield SimpleNamespace(app=app,client=client,instance=instance,gateway=gateway,
                              receiver=receiver,settings=settings)
    assert not receiver.requests and not gateway.sent


@pytest.fixture
def transport(monkeypatch):
    instances={};observations=[]
    def register(item):
        port=item.instance['port']
        instances[f'127.0.0.1:{port}']=item
        instances[f'127.0.0.1:{port+1}']=item
        instances[urlsplit(item.settings.public_url).netloc]=item
    def urlopen(request,timeout):
        url=request.full_url;parsed=urlsplit(url)
        assert parsed.netloc in instances, 'Unexpected external HTTP request'
        item=instances[parsed.netloc]
        if parsed.netloc==f"127.0.0.1:{item.instance['port']+1}":
            assert parsed.path=='/api/sessions/default'
            return io.BytesIO(json.dumps({'status':item.gateway.status()}).encode())
        response=item.client.request(request.get_method(),parsed.path,headers=dict(request.header_items()))
        observations.append((item.instance['slug'],parsed.path,response.status_code))
        if response.status_code>=400:
            raise HTTPError(url,response.status_code,'Synthetic ASGI response',response.headers,io.BytesIO(response.content))
        return io.BytesIO(response.content)
    monkeypatch.setattr(release.urllib.request,'urlopen',urlopen)
    monkeypatch.setattr(release,'active',lambda unit:True)
    def wait_for_preparation(delay):
        # Keep the real wait budget while ASGI preparation is pending. Terminal
        # states need no artificial delay, including the deliberate failure case.
        deadline=time.monotonic()+delay
        while any(item.app.state.readiness.state in ('waiting','preparing')
                  for item in instances.values()):
            remaining=deadline-time.monotonic()
            if remaining<=0: return
            Event().wait(min(.01,remaining))
    # Preserve the real bounded wait loop and real health/readiness decisions.
    monkeypatch.setattr(release,'time',SimpleNamespace(time=time.time,time_ns=time.time_ns,
                                                    sleep=wait_for_preparation))
    return SimpleNamespace(register=register,observations=observations)


def wait_state(item,state):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=item.client.get('/healthz')
        assert result.status_code==200
        payload=result.json()
        if payload['readiness']['state']==state: return payload
        Event().wait(.01)
    pytest.fail('Actual ASGI readiness did not reach '+state)


def test_real_health_payload_keeps_preparation_closed_then_passes_release_health(environment,tmp_path,transport):
    gate=tmp_path/'gate';gate.touch();entered=Event();finish=Event()
    def configure(service):
        repair=service.store._repair_revocation_derivatives
        def blocked_repair():
            entered.set()
            assert finish.wait(5)
            repair()
        service.store._repair_revocation_derivatives=blocked_repair
    with runtime(environment,tmp_path,'preparation',8820,gate,configure=configure) as item:
        transport.register(item)
        try:
            assert wait_state(item,'waiting')['readiness']['ready'] is False
            assert release.health(item.instance,__version__,maintenance=True)=='WORKING'
            with pytest.raises(ReleaseError):
                release.health(item.instance,__version__,maintenance=True,require_ready=True)
            gate.unlink();assert entered.wait(5)
            pending=wait_state(item,'preparing')['readiness']
            assert pending['ready'] is False and not any(pending['workers'].values())
            assert item.client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==503
            with pytest.raises(ReleaseError): release.health(item.instance,__version__,require_ready=True)
        finally: finish.set()
        ready=wait_state(item,'ready')['readiness']
        assert ready['ready'] is True and all(ready['workers'].values())
        assert item.client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==401
        assert release.wait_health([item.instance],__version__,{'preparation':'WORKING'},require_ready=True)=={'preparation':'WORKING'}


def test_actual_failed_preparation_is_rejected_by_release_wait_and_admission(environment,tmp_path,transport):
    gate=tmp_path/'gate';gate.touch()
    def configure(service):
        def fail(): raise RuntimeError('synthetic private failure detail')
        service.store._repair_revocation_derivatives=fail
    with runtime(environment,tmp_path,'failure',8820,gate,configure=configure) as item:
        transport.register(item);gate.unlink()
        payload=wait_state(item,'failed')
        assert payload['readiness']['error_code']=='REVOCATION_REPAIR_FAILED'
        assert 'synthetic private' not in json.dumps(payload)
        assert not any(payload['readiness']['workers'].values())
        assert item.client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==503
        assert item.client.post('/webhooks/waha',json={}).status_code==503
        with pytest.raises(ReleaseError):
            release.wait_health([item.instance],__version__,{'failure':'WORKING'},require_ready=True)


@pytest.mark.parametrize('failed,preparation_delay',[(False,0),(True,0),(False,.8)],
                         ids=['both-ready','one-failed','delayed-ready'])
def test_transaction_consumes_real_two_instance_readiness(environment,tmp_path,monkeypatch,transport,release_sandbox,failed,preparation_delay):
    root,candidate,instances,_,_,commands=release_sandbox
    # Reuse its filesystem isolation, but use the actual current schema for the
    # live ASGI applications. Migration/identity checks remain real.
    (candidate/'deploy/migrations.json').write_text(json.dumps({'schemaVersion':8,'migrations':[]}))
    (candidate/'sally_whatsapp/store.py').write_text('SCHEMA='+repr(SCHEMA))
    transaction.gate_on()
    clients=[]
    with ExitStack() as stack:
        runtime_specs=[]
        for index,instance in enumerate(instances):
            path=instance['path'];path.unlink()
            store=Store(path,migrate_schema=False)
            store.ingest(message('preserved-'+instance['slug']),historical=True)
            settings,config=runtime_configuration(environment,tmp_path,instance['slug'],8820+index*2,
                                                  database=path,registered=True)
            # Real offline enrollment binds the current schema to this tenant
            # before the real unprivileged snapshot worker opens the database.
            register_external_identity(settings)
            instance.update(config=str(config),port=8820+index*2)
            def configure(service,broken=failed and index==1):
                if preparation_delay:
                    repair=service.store._repair_revocation_derivatives
                    def delayed_repair():
                        Event().wait(preparation_delay)
                        repair()
                    service.store._repair_revocation_derivatives=delayed_repair
                if broken:
                    def fail(): raise RuntimeError('synthetic preparation failure')
                    service.store._repair_revocation_derivatives=fail
            runtime_specs.append((instance,8820+index*2,path,configure))
        # Real systemd constructs the new Service after the frozen database has
        # been replaced. Keeping an old Service alive across that replacement
        # would correctly trip its continuity guard, and would not model a
        # stopped/restarted process. HTTP/readiness still use actual ASGI apps.
        original_run=transaction.run
        def run(command,**kwargs):
            result=original_run(command,**kwargs)
            if command[:2]==['systemctl','start'] and not clients:
                for instance,port,path,configure in runtime_specs:
                    item=stack.enter_context(runtime(environment,tmp_path,instance['slug'],port,
                                                     transaction.GATE,database=path,configure=configure,registered=True))
                    instance.update(item.instance)
                    transport.register(item);clients.append(item)
            return result
        monkeypatch.setattr(transaction,'run',run)
        before={item['slug']:'WORKING' for item in instances}
        phases=[];checkpoint=transaction.checkpoint
        def record(plan,phase):
            phases.append(phase);checkpoint(plan,phase)
        monkeypatch.setattr(transaction,'checkpoint',record)
        def activate():
            try:
                return transaction.activate(root,candidate,instances,instances,before,'0.3.3',__version__,
                                            tmp_path/'record',release.wait_health,lambda _:None,lambda _:None,
                                            source_commit='a'*40)
            except ReleaseError as error:
                error.add_note('Actual synthetic readiness: '+json.dumps({
                    item.instance['slug']:item.app.state.readiness.snapshot() for item in clients}))
                raise
        if failed:
            with pytest.raises(ReleaseError): activate()
            plan=json.loads(transaction.JOURNAL.read_text())
            assert plan['phase']=='committed' and plan['activationError']=='activation_not_verified'
            assert 'published' not in phases
            assert not (transaction.STATE/'whatsapp/current.json').exists()
            assert wait_state(clients[0],'ready')['readiness']['ready'] is True
            assert wait_state(clients[1],'failed')['readiness']['ready'] is False
            assert clients[0].client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==401
            assert clients[1].client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==503
            # A ready instance may already accept data: recovery must not roll
            # its database or code back after this boundary.
            clients[0].app.state.service.store.ingest(message('after-activation'),historical=True)
            with pytest.raises(ReleaseError): transaction.recover(plan,release.wait_health)
            assert clients[0].app.state.service.store.message('after-activation') is not None
            assert plan['phase']=='committed' and plan['activationError']=='activation_not_verified'
            assert 'published' not in phases
        else:
            assert activate()['phase']=='published'
            assert phases[-1]=='published'
            for item in clients: assert item.client.get('/mcp',headers={'Accept':'text/event-stream'}).status_code==401
        assert (root/'sally_whatsapp/marker').read_text()=='new'
        assert not transaction.GATE.exists()
        for item in clients:
            assert item.app.state.service.store.message('preserved-'+item.instance['slug']) is not None
        assert ['systemctl','start',*[item['unit'] for item in instances]] in commands
