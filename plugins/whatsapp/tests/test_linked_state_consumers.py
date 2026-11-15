"""Synthetic visibility races at media and webhook boundaries; no real sessions."""
from datetime import datetime, timezone
import json
import time

import pytest

from conftest import attachment_payload, install_attachment_readback, message
from sally_whatsapp.event_recovery import EventRecovery
from sally_whatsapp.server import Service
from test_event_policies import direct_subscribe, LEGACY
from test_revoked_media_metadata import attachment, CONTENT, NAME, raw, revoke
from test_reaction_revocation_regressions import reaction, original, ORIGINAL, CHAT


@pytest.fixture
def linked(environment, monkeypatch):
    service=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    hidden=set()
    # Model the Store visibility contract independently to exercise precisely
    # the consumer's second checks and races, without encoding its persistence.
    monkeypatch.setattr(service.store,'is_unavailable',
        lambda db, identifier, **context: service.store.is_revoked(db,identifier) or identifier in hidden,
        raising=False)
    monkeypatch.setattr(service.store,'remember_message_context',lambda *a,**k: None,raising=False)
    service.gateway.media_bytes=CONTENT
    return service,hidden,environment[1]


@pytest.mark.parametrize('stage',['queued','ready'])
def test_linked_exclusion_hides_media_without_destroying_private_cache(linked,stage):
    service,hidden,_=linked
    identifier=attachment(service)
    grant=None
    if stage=='ready':
        assert service.media.process_one()
        grant=service.media.status(identifier,'test-owner')['download_url'].rsplit('/',1)[-1]
    before=raw(service,identifier)
    hidden.add('false_group-1@g.us_SYNTHETICSOURCE')
    status=service.media.status(identifier,'test-owner')
    assert status['state']=='unavailable'
    assert status['filename']==status['mimetype']==''
    assert status['size'] is None and status['sha256'] is None
    assert 'download_url' not in status and 'next_tool' not in status
    assert raw(service,identifier)==before
    with pytest.raises(ValueError,match='not ready'):
        service.media.url(identifier,'test-owner')
    if grant:
        with pytest.raises(ValueError,match='not ready'): service.media.resolve(grant)
        assert service.media.path(identifier).read_bytes()==CONTENT
    else:
        assert not service.media.process_one()
    with pytest.raises(ValueError,match='not found'):
        service.media.status(identifier,'different-owner')
    hidden.clear()
    assert service.media.status(identifier,'test-owner')['filename']==NAME
    if stage=='queued': assert service.media.process_one()
    assert service.media.status(identifier,'test-owner')['state']=='ready'


def test_excluded_media_cannot_be_enqueued_again(linked):
    service,hidden,_=linked
    hidden.add('false_group-1@g.us_SYNTHETICSOURCE')
    with pytest.raises(ValueError,match='unavailable'):
        attachment(service)
    with service.store.db() as db:
        assert db.execute('SELECT count(*) FROM media_jobs').fetchone()[0]==0


@pytest.mark.parametrize('failure',[False,True])
def test_exclusion_during_download_keeps_retry_source_private_and_reversible(linked,failure):
    service,hidden,_=linked
    identifier=attachment(service)
    before=raw(service,identifier)
    original=service.gateway.attachment_to_file
    def downloading(media,target,maximum):
        result=original(media,target,maximum)
        hidden.add('false_group-1@g.us_SYNTHETICSOURCE')
        if failure: raise ValueError('synthetic failed transfer')
        return result
    service.gateway.attachment_to_file=downloading
    assert service.media.process_one()
    after=raw(service,identifier)
    assert after['state']=='queued' and after['source']==before['source']
    assert after['filename']==NAME
    assert not service.media.path(identifier).exists()
    assert not service.media.process_one()
    hidden.clear()
    service.gateway.attachment_to_file=original
    assert service.media.process_one()
    assert service.media.status(identifier,'test-owner')['state']=='ready'


def test_hidden_queued_job_does_not_starve_visible_transfers(linked):
    service,hidden,_=linked
    first=attachment(service,'false_group-1@g.us_HIDDENSOURCE')
    second=attachment(service,'false_group-1@g.us_VISIBLESOURCE')
    hidden.add('false_group-1@g.us_HIDDENSOURCE')
    assert service.media.process_one()
    assert raw(service,first)['state']=='queued'
    assert raw(service,second)['state']=='ready'


def test_revocation_retains_existing_irreversible_redaction_contract(linked):
    service,_,_=linked
    identifier=attachment(service)
    assert service.media.process_one()
    revoke(service)
    assert service.media.status(identifier,'test-owner')['state']=='cancelled'
    assert raw(service,identifier)['filename']==''
    assert not service.media.path(identifier).exists()


@pytest.mark.parametrize('name',['message.received','message.digest'])
def test_hidden_message_callbacks_never_post_or_redact_archive(linked,name):
    service,hidden,receiver=linked
    filters={**LEGACY,**({'digest_window_seconds':60} if name=='message.digest' else {})}
    direct_subscribe(service,filters,name)
    service.store.ingest(message('hidden-callback',text='synthetic retained content'))
    receiver.requests.clear()
    hidden.add('hidden-callback')
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET next_attempt=0')
    assert service.events.dispatch_one()
    assert receiver.requests==[]
    with service.store.db() as db:
        row=db.execute('SELECT state,attempts FROM deliveries').fetchone()
        assert tuple(row)==('cancelled',0)
        assert db.execute("SELECT body FROM messages WHERE id='hidden-callback'").fetchone()[0]=='synthetic retained content'


def test_callback_rechecks_exclusion_after_claim(linked,monkeypatch):
    service,hidden,receiver=linked
    direct_subscribe(service,LEGACY)
    service.store.ingest(message('hidden-after-claim'))
    receiver.requests.clear()
    decrypt=service.events.cipher.decrypt
    def claimed(secret,*args,**kwargs):
        hidden.add('hidden-after-claim')
        return decrypt(secret,*args,**kwargs)
    monkeypatch.setattr(service.events.cipher,'decrypt',claimed)
    assert service.events.dispatch_one()
    assert receiver.requests==[]
    with service.store.db() as db:
        assert tuple(db.execute('SELECT state,attempts FROM deliveries').fetchone())==('cancelled',1)


def test_recovery_cannot_restore_hidden_delivery_or_change_history(linked):
    service,hidden,_=linked
    subscription=direct_subscribe(service,LEGACY)['id']
    service.store.ingest(message('recover-hidden'))
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',last_status=503,attempts=?",(service.settings.max_callback_attempts,))
        identifier=db.execute('SELECT id FROM deliveries').fetchone()[0]
    recovery=EventRecovery(service.store,service.settings)
    assert recovery.preview(subscription,[identifier])['eligible']
    hidden.add('recover-hidden')
    blocked=recovery.preview(subscription,[identifier])
    assert not blocked['eligible']
    assert blocked['deliveries'][0]['reason']=='source_unavailable'
    with service.store.db() as db:
        assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='failed'
        assert db.execute("SELECT body FROM messages WHERE id='recover-hidden'").fetchone()[0]


def test_administrative_permit_is_rechecked_for_linked_exclusion(linked):
    service,hidden,receiver=linked
    subscription=direct_subscribe(service,LEGACY)['id']
    service.store.ingest(message('recover-permitted'))
    with service.store.db() as db:
        db.execute("UPDATE deliveries SET state='failed',last_status=503,attempts=?",(service.settings.max_callback_attempts,))
        identifier=db.execute('SELECT id FROM deliveries').fetchone()[0]
    recovery=EventRecovery(service.store,service.settings)
    preview=recovery.preview(subscription,[identifier])
    recovery.execute(subscription,[identifier],fingerprint=preview['fingerprint'],request_id='synthetic-linked-recovery')
    hidden.add('recover-permitted')
    receiver.requests.clear()
    assert service.events.dispatch_one()
    assert receiver.requests==[]
    with service.store.db() as db:
        assert tuple(db.execute('SELECT state,attempts FROM deliveries').fetchone())==('cancelled',service.settings.max_callback_attempts)


@pytest.mark.parametrize('recovery',[False,True])
def test_reaction_uses_target_visibility_not_reaction_id(linked,recovery):
    service,hidden,receiver=linked
    subscription=direct_subscribe(service,{'chat_ids':[CHAT],'event_types':['message.reaction']},'whatsapp.event')['id']
    service.store.ingest(original())
    service.store.ingest(reaction())
    receiver.requests.clear()
    hidden.add(ORIGINAL)
    if recovery:
        with service.store.db() as db:
            db.execute("UPDATE deliveries SET state='failed',last_status=503,attempts=?",(service.settings.max_callback_attempts,))
            identifier=db.execute('SELECT id FROM deliveries').fetchone()[0]
        result=EventRecovery(service.store,service.settings).preview(subscription,[identifier])
        assert result['deliveries'][0]['reason']=='source_unavailable'
    else:
        assert service.events.dispatch_one()
        with service.store.db() as db:
            assert db.execute('SELECT state FROM deliveries').fetchone()[0]=='cancelled'
    assert not receiver.requests
    with service.store.db() as db:
        assert 'synthetic original text'==db.execute('SELECT body FROM messages WHERE id=?',(ORIGINAL,)).fetchone()[0]
        assert 'reaction' in db.execute('SELECT data FROM account_events').fetchone()[0]


@pytest.mark.parametrize('kind',['DeleteChat','ClearChat','DeleteForMe'])
def test_provider_deletion_blocks_unarchived_ready_media_by_retained_provenance(environment,kind):
    service=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    chat='15550001111@c.us'
    identifier='false_'+chat+'_SYNTHETIC'
    now=time.time()
    install_attachment_readback(service.gateway,attachment_payload(identifier,chat,service.gateway.media_bytes,
        name=NAME,timestamp=int(now)-20))
    source={'kind':'gateway','message_id':identifier,'chat_id':chat,'timestamp':int(now)-20,
            'media':{'url':'http://synthetic.invalid/media','filename':NAME}}
    transfer=service.media.enqueue('test-owner',source,NAME)['id']
    assert service.media.process_one()
    before=raw(service,transfer)
    at=datetime.fromtimestamp(now,timezone.utc).isoformat()
    if kind=='DeleteForMe':
        data={'ChatJID':'15550001111@s.whatsapp.net','MessageID':'SYNTHETIC',
              'IsFromMe':False,'Timestamp':at,'Action':{'messageTimestamp':int(now)-20}}
    else:
        data={'JID':'15550001111@s.whatsapp.net','Timestamp':at,
              'Action':{'messageRange':{'messages':[{'key':{'ID':'SYNTHETIC','fromMe':False}}]}}}
    service.store.ingest({'id':'synthetic-engine-'+kind,'event':'engine.event','engine':'GOWS',
                          'session':'default','payload':{'session':'default','event':'events.'+kind,'data':data}})
    assert service.media.status(transfer,'test-owner')['state']=='unavailable'
    assert raw(service,transfer)==before
    assert service.media.path(transfer).is_file()
    with service.store.db() as db:
        assert not service.store.is_revoked(db,identifier)
        assert db.execute('SELECT count(*) FROM messages').fetchone()[0]==0


def test_unknown_original_timestamp_blocks_download_after_known_chat_deletion(environment):
    service=Service(environment[0],gateway=environment[2],event_transport=environment[1])
    now=time.time()
    chat='15550001111@c.us'
    identifier='false_'+chat+'_SYNTHETIC'
    transfer=service.media.enqueue('test-owner',{'kind':'gateway','message_id':identifier,'chat_id':chat},NAME)['id']
    service.store.ingest({'id':'synthetic-late-context','event':'engine.event','engine':'GOWS','session':'default',
        'payload':{'session':'default','event':'events.DeleteChat','data':{'JID':chat,
            'Timestamp':datetime.fromtimestamp(now,timezone.utc).isoformat()}}})
    service.gateway.message=lambda *a,**k: {'id':identifier,'timestamp':int(now)-20,
        'media':{'url':'http://synthetic.invalid/media','filename':NAME}}
    service.gateway.attachment_to_file=lambda *a,**k: pytest.fail('Excluded source must not download')
    assert not service.media.process_one()
    assert service.media.status(transfer,'test-owner')['state']=='unavailable'
    assert raw(service,transfer)['state']=='queued'
    assert raw(service,transfer)['source']


@pytest.mark.parametrize('attempts',[0,1])
def test_mixed_digest_preserves_visible_members_before_attempt_and_signals_later_cancellation(linked,attempts):
    service,hidden,receiver=linked
    direct_subscribe(service,{**LEGACY,'digest_window_seconds':60},'message.digest')
    service.store.ingest(message('digest-A'))
    service.store.ingest(message('digest-B'))
    receiver.requests.clear()
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET next_attempt=0,attempts=?',(attempts,))
        before=dict(db.execute('SELECT * FROM deliveries').fetchone())
    hidden.add('digest-A')
    assert service.events.dispatch_one()
    with service.store.db() as db:
        after=dict(db.execute('SELECT * FROM deliveries').fetchone())
    assert after['event_id']==before['event_id']
    if attempts==0:
        assert after['state']=='accepted' and after['attempts']==1
        assert json.loads(receiver.requests[0][1])['data']['message_ids']==['digest-B']
    else:
        assert receiver.requests==[]
        assert after['state']=='cancelled' and after['attempts']==attempts
        assert after['body']==before['body']
        assert service.store.state()['recovery_reasons']['digest_cancelled_after_attempt']['status']=='open'


def test_mixed_digest_exclusion_after_claim_preserves_payload_and_signals_recovery(linked,monkeypatch):
    service,hidden,receiver=linked
    direct_subscribe(service,{**LEGACY,'digest_window_seconds':60},'message.digest')
    service.store.ingest(message('digest-A'))
    service.store.ingest(message('digest-B'))
    receiver.requests.clear()
    with service.store.db() as db:
        db.execute('UPDATE deliveries SET next_attempt=0')
        before=dict(db.execute('SELECT * FROM deliveries').fetchone())
    decrypt=service.events.cipher.decrypt
    def hide_after_claim(*args,**kwargs):
        hidden.add('digest-A')
        return decrypt(*args,**kwargs)
    monkeypatch.setattr(service.events.cipher,'decrypt',hide_after_claim)
    assert service.events.dispatch_one()
    with service.store.db() as db: after=dict(db.execute('SELECT * FROM deliveries').fetchone())
    assert receiver.requests==[] and after['body']==before['body']
    assert after['state']=='cancelled' and after['attempts']==1
    assert service.store.state()['recovery_reasons']['digest_cancelled_after_attempt']['status']=='open'
