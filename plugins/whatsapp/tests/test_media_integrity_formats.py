"""Real synthetic file bytes; all provider/native-file requests are replaced."""
import base64
import copy
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import struct
import wave
import zipfile
import xml.etree.ElementTree as ET

import pytest
from starlette.testclient import TestClient

from conftest import call
from sally_whatsapp.live_attachments import archive_media_identity, read_source
from sally_whatsapp.media import copy_bounded, mime
from sally_whatsapp.server import create_app


FIXTURES=Path(__file__).parent/'fixtures'/'media-integrity'
FILES=json.loads((FIXTURES/'manifest.json').read_text())
CHAT='15550001111@c.us'
FLAGS={'IsViewOnce':False,'IsViewOnceV2':False,'IsViewOnceV2Extension':False,'IsEphemeral':False}


def result(client,name,args):
    value=call(client,name,args)['result']
    assert not value.get('isError'),value
    return value['structuredContent']


def observe(item,*,outgoing=False):
    kind=('audioMessage' if item['name'].endswith(('.ogg','.wav')) else
          'videoMessage' if item['name'].endswith('.mp4') else
          'stickerMessage' if item['name'].endswith('.webp') else
          'imageMessage' if item['name'].endswith(('.png','.jpg')) else 'documentMessage')
    return {'id':f'{str(outgoing).lower()}_{CHAT}_MEDIAFORMAT','timestamp':1000,
            'fromMe':outgoing,'from':'15550002222@c.us' if outgoing else CHAT,
            'to':CHAT if outgoing else '15550002222@c.us','body':'Synthetic attachment',
            'hasMedia':True,'media':{'url':'http://127.0.0.1:8821/api/files/synthetic',
                                   'mimetype':item['mime'],'filename':item['name']},
            '_data':{**FLAGS,'Message':{kind:{
                'fileSHA256':base64.b64encode(bytes.fromhex(item['sha256'])).decode(),
                'fileLength':str(item['size']),'mimetype':item['mime'],'fileName':item['name']}}}}


def setup(environment,item,*,outgoing=False):
    settings,receiver,gateway,token=environment
    settings=replace(settings,live_account_enabled=True,send_enabled=True,allow_all_destinations=True)
    gateway.observation=observe(item,outgoing=outgoing)
    gateway.media_bytes=(FIXTURES/item['name']).read_bytes()
    gateway.requests=[]
    gateway.downloads=[]
    def request(method,path,**kwargs):
        assert method=='GET'
        gateway.requests.append((method,path,kwargs))
        return copy.deepcopy(gateway.observation)
    def download(media,target,maximum):
        gateway.downloads.append(media)
        return copy_bounded([gateway.media_bytes],target,maximum,len(gateway.media_bytes))
    gateway.request=request
    gateway.attachment_to_file=download
    app=create_app(settings,gateway=gateway,event_transport=receiver,start_worker=False)
    return app,gateway,token


def acquire(service,gateway):
    service.store.ingest({'id':'synthetic-media-event','event':'message.any',
                          'session':'default','payload':copy.deepcopy(gateway.observation)})


def headers(client,token):
    client.headers.update({'Authorization':'Bearer '+token(),
                           'Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2026-07-28'})


@pytest.mark.parametrize('changed',['timestamp','digest','revoked','no_acquisition'])
def test_archive_incomplete_clear_requires_acquired_proof_before_and_after_read(environment,changed):
    from test_clearchat_coverage import clear
    item=next(x for x in FILES if x['name']=='sample.pdf')
    app,gateway,_=setup(environment,item)
    service=app.state.service
    identifier=gateway.observation['id']
    expected=archive_media_identity(gateway.observation)
    if changed!='no_acquisition':
        acquire(service,gateway)
    service.store.ingest(clear(through=None))
    original=gateway.request
    def raced(*args,**kwargs):
        observation=original(*args,**kwargs)
        if changed=='revoked':
            service.store.ingest({'event':'message.revoked','payload':{'revokedMessageId':identifier}})
        else:
            with service.store.db() as db:
                if changed=='timestamp':
                    db.execute('UPDATE messages SET timestamp=timestamp+1 WHERE id=?',(identifier,))
                elif changed=='digest':
                    metadata=json.loads(db.execute('SELECT media FROM messages WHERE id=?',(identifier,)).fetchone()[0])
                    metadata['identity']={**expected,'sha256':'0'*64}
                    db.execute('UPDATE messages SET media=? WHERE id=?',(json.dumps(metadata),identifier))
        return observation
    gateway.request=raced
    with pytest.raises(ValueError,match='removed|expired|visibility'):
        read_source(service.store,service.settings,gateway,identifier,expected_timestamp=1000,
                    expected_media=expected,acquired_source=True)
    assert not gateway.downloads
    assert len(gateway.requests)==(0 if changed=='no_acquisition' else 1)


@pytest.mark.parametrize('item',FILES,ids=lambda x:x['name'])
@pytest.mark.parametrize('source',['archive','live'])
@pytest.mark.parametrize('outgoing',[False,True],ids=['received','sent'])
def test_real_format_bytes_mcp_to_signed_download(environment,item,source,outgoing):
    app,gateway,token=setup(environment,item,outgoing=outgoing)
    with TestClient(app) as client:
        headers(client,token)
        if source=='archive':
            acquire(app.state.service,gateway)
        transfer=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':source})
        assert app.state.service.media.process_one()
        status=call(client,'get_transfer_status',{'transfer_id':transfer['id']})['result']
        assert not status.get('isError'),status
        ready=status['structuredContent']
        assert ready['state']=='ready'
        assert (ready['sha256'],ready['size'],ready['mimetype'],ready['filename'])==(
            item['sha256'],item['size'],item['mime'],item['name'])
        images=[block for block in status['content'] if block['type']=='image']
        inline=item['mime'] in {'image/jpeg','image/png','image/webp'}
        assert len(images)==int(inline)
        if inline:
            assert images[0]['mimeType']==item['mime']
            assert base64.b64decode(images[0]['data'],validate=True)==(FIXTURES/item['name']).read_bytes()
        client.headers.pop('Authorization')
        response=client.get(ready['download_url'])
        assert response.status_code==200
        assert response.content==(FIXTURES/item['name']).read_bytes()
        assert hashlib.sha256(response.content).hexdigest()==item['sha256']
        assert response.headers['content-type'].split('; charset=',1)[0]==item['mime']
        assert item['name'] in response.headers['content-disposition']
        assert response.headers['x-content-type-options']=='nosniff'
        assert response.headers['cache-control']=='private, no-store'
        assert not gateway.sent and not environment[1].requests
        if source=='archive':
            assert len(gateway.requests)==2  # ready/status/download use the verified cache
        else:
            # Inline bytes revalidate the live source before and after reading.
            assert len(gateway.requests)==5+2*int(inline)


@pytest.mark.parametrize('source',['archive','live'])
def test_archive_and_live_reject_download_bytes_with_wrong_digest(environment,source):
    item=next(x for x in FILES if x['name']=='sample.pdf')
    app,gateway,token=setup(environment,item)
    with TestClient(app) as client:
        headers(client,token)
        if source=='archive': acquire(app.state.service,gateway)
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':source})
        gateway.media_bytes=b'different synthetic file bytes'
        assert app.state.service.media.process_one()
        status=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert status['state']=='failed' and status['sha256'] is None
        assert 'download_url' not in status
        assert not app.state.service.media.path(queued['id']).exists()


def test_archive_preserves_acquired_digest_when_provider_replaces_file(environment):
    item=next(x for x in FILES if x['name']=='sample.pdf')
    app,gateway,token=setup(environment,item)
    with TestClient(app) as client:
        headers(client,token)
        acquire(app.state.service,gateway)
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':'archive'})
        gateway.media_bytes=b'replaced synthetic file'
        gateway.observation['_data']['Message']['documentMessage']['fileSHA256']=base64.b64encode(
            hashlib.sha256(gateway.media_bytes).digest()).decode()
        assert app.state.service.media.process_one()
        assert result(client,'get_transfer_status',{'transfer_id':queued['id']})['state']=='failed'
        assert not gateway.downloads


@pytest.mark.parametrize('field,value',[('mimetype','image/jpeg'),('fileName','different.jpg'),('fileLength','1')])
@pytest.mark.parametrize('source',['archive','live'])
def test_provider_metadata_conflict_never_produces_ready_file(environment,field,value,source):
    item=next(x for x in FILES if x['name']=='sample.pdf')
    app,gateway,token=setup(environment,item)
    with TestClient(app) as client:
        headers(client,token)
        if source=='archive': acquire(app.state.service,gateway)
        gateway.observation['_data']['Message']['documentMessage'][field]=value
        response=call(client,'get_attachment',{'message_id':gateway.observation['id'],'source':source})['result']
        if response.get('isError'):
            assert source=='live' and field!='fileLength'
            assert not gateway.downloads
        else:
            queued=response['structuredContent']
            assert app.state.service.media.process_one()
            assert result(client,'get_transfer_status',{'transfer_id':queued['id']})['state']=='failed'
            assert not app.state.service.media.path(queued['id']).exists()


@pytest.mark.parametrize('available',[True,False])
def test_legacy_ready_cache_requires_verification_without_new_send(environment,available):
    item=next(x for x in FILES if x['name']=='sample.pdf')
    app,gateway,token=setup(environment,item)
    with TestClient(app) as client:
        headers(client,token);acquire(app.state.service,gateway)
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':'archive'})
        assert app.state.service.media.process_one()
        with app.state.service.store.db() as db:
            db.execute("UPDATE media_jobs SET source=X'' WHERE id=?",(queued['id'],))
        before=len(gateway.requests)
        if not available:
            def unavailable(*args,**kwargs): raise TimeoutError()
            gateway.request=unavailable
        status=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert app.state.service.media.path(queued['id']).read_bytes()==gateway.media_bytes
        assert status['id']==queued['id']
        if available:
            assert status['state']=='ready' and len(gateway.requests)==before+1
            assert client.get(status['download_url']).content==gateway.media_bytes
            assert len(gateway.requests)==before+1
        else:
            assert status['state']=='legacy_unverified' and status['sha256'] is None
            assert 'download_url' not in status
        assert not gateway.sent and not app.state.service.process_action()


@pytest.mark.parametrize('item',FILES,ids=lambda x:x['name'])
def test_native_format_transfer_to_media_wire_and_download(environment,monkeypatch,item):
    app,gateway,token=setup(environment,item)
    payload=(FIXTURES/item['name']).read_bytes()
    monkeypatch.setattr('sally_whatsapp.media.download_public',
                        lambda url,path,maximum:copy_bounded([payload],path,maximum,len(payload)))
    outgoing=[]
    def request(method,path,**kwargs):
        outgoing.append((method,path,kwargs['json']))
        return {'id':f'true_{CHAT}_SYNTHETICSEND'}
    gateway.request=request
    operation=('messages_send_voice' if item['name'].endswith(('.ogg','.wav')) else
               'messages_send_video' if item['name'].endswith('.mp4') else
               'messages_send_image' if item['name'].endswith(('.png','.jpg')) else
               'messages_send_sticker' if item['name'].endswith('.webp') else 'messages_send_file')
    body={'chatId':CHAT}
    if operation in ('messages_send_voice','messages_send_video'):
        body['convert']=item['name'].endswith('.wav')
    with TestClient(app) as client:
        headers(client,token)
        queued=result(client,'prepare_file',{'file':{'file_id':'file-synthetic-'+item['name'],
            'download_url':'https://files.example/synthetic','mime_type':item['mime'],'file_name':item['name']}})
        assert app.state.service.media.process_one()
        ready=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert (ready['sha256'],ready['size'],ready['mimetype'])==(item['sha256'],item['size'],item['mime'])
        assert client.get(ready['download_url']).content==payload
        args={'operation':operation,'arguments':{'body':body},'transfer_id':queued['id'],
              'idempotency_key':'synthetic-format-send-001'}
        assert result(client,'send_media',args)['state']=='queued'
        assert app.state.service.process_action()
        assert result(client,'send_media',args)['state']=='submitted'
        assert not app.state.service.process_action() and len(outgoing)==1
        assert outgoing[0][2]['file']['mimetype']==item['mime']
        assert outgoing[0][2]['file']['filename']==item['name']
        assert not environment[1].requests


@pytest.mark.parametrize('value,expected',[
    ('audio/ogg; codecs=opus','audio/ogg; codecs=opus'),
    ('Audio/OGG; codecs="OPUS"','audio/ogg; codecs=opus'),
    ('audio/ogg; codecs=vorbis','audio/ogg'),
    ('audio/wav; codecs=opus','audio/wav'),
    ('audio/ogg; codecs=opus; codecs=vorbis','audio/ogg'),
    ('audio/ogg; codecs="""opus"""','audio/ogg'),
    ('audio/ogg\r\nX-Injected: yes','application/octet-stream'),
    ('audio/ogg; codecs=opus\x7f','application/octet-stream'),
])
def test_voice_mime_preserves_only_valid_supported_codec_parameter(value,expected):
    assert mime(value,'fixture.ogg')==expected


def test_archive_identity_is_minimal_and_not_derived_from_unrelated_metadata():
    item=FILES[0];observed=observe(item)
    assert archive_media_identity(observed)=={'type':'documentMessage','sha256':item['sha256']}
    assert archive_media_identity({'media':{'identity':{'type':'documentMessage','sha256':item['sha256']}}}) is None
    assert archive_media_identity({'_data':{'Message':{'extendedTextMessage':{'contextInfo':{
        'quotedMessage':observed['_data']['Message']}}}}}) is None


def test_fixture_formats_are_real_packages_and_media_headers():
    for item in FILES:
        content=(FIXTURES/item['name']).read_bytes()
        assert len(content)==item['size'] and hashlib.sha256(content).hexdigest()==item['sha256']
    with zipfile.ZipFile(FIXTURES/'sample.docx') as document:
        assert document.testzip() is None
        for name in ('[Content_Types].xml','_rels/.rels','word/document.xml'):
            ET.fromstring(document.read(name))
    pdf=(FIXTURES/'sample.pdf').read_bytes()
    offset=int(pdf.split(b'startxref\n')[1].splitlines()[0])
    assert pdf.startswith(b'%PDF-1.4') and pdf[offset:].startswith(b'xref\n')
    assert pdf.rstrip().endswith(b'%%EOF')
    with wave.open(io.BytesIO((FIXTURES/'sample.wav').read_bytes())) as audio:
        assert audio.getframerate()==48000 and audio.getnchannels()==1
        assert len(audio.readframes(audio.getnframes()))==19200
    ogg=(FIXTURES/'sample.ogg').read_bytes()
    assert ogg.startswith(b'OggS') and b'OpusHead' in ogg[:128]
    assert b'ftyp' in (FIXTURES/'sample.mp4').read_bytes()[:32]
    assert (FIXTURES/'sample.png').read_bytes().startswith(b'\x89PNG\r\n\x1a\n')
    assert (FIXTURES/'sample.jpg').read_bytes().startswith(b'\xff\xd8')
    assert (FIXTURES/'sample.webp').read_bytes()[8:12]==b'WEBP'
