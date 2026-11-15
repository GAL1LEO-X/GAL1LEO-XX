"""Original Lottie ZIP contract across source verification and signed download."""
import base64
import hashlib
import io
import json
import zipfile

import pytest
from starlette.testclient import TestClient

from conftest import call
from test_media_integrity_formats import FILES, FIXTURES, acquire, headers, result, setup


def lottie_zip():
    animation={'v':'5.7.4','fr':30,'ip':0,'op':1,'w':16,'h':16,'layers':[]}
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w',compression=zipfile.ZIP_STORED) as archive:
        member=zipfile.ZipInfo('animation/animation.json',(2026,1,1,0,0,0))
        member.compress_type=zipfile.ZIP_STORED
        archive.writestr(member,json.dumps(animation,separators=(',',':')).encode())
    content=output.getvalue()
    # Same valid synthetic source as WAHA lottie-original.test.cjs.
    assert hashlib.sha256(content).hexdigest()=='871dadc43c21b2356b094b2702e40927fa2483a792918f9655ea2ea294f73f74'
    return content


def setup_lottie(environment,*,outgoing=False):
    app,gateway,token=setup(environment,next(item for item in FILES if item['name']=='sample.webp'),outgoing=outgoing)
    gateway.media_bytes=lottie_zip()
    gateway.observation['media'].update(mimetype='application/was',filename='MEDIAFORMAT.zip')
    gateway.observation['_data']['Message']={'stickerMessage':{
        'mimetype':'application/was','fileLength':str(len(gateway.media_bytes)),
        'fileSHA256':base64.b64encode(hashlib.sha256(gateway.media_bytes).digest()).decode(),
    }}
    return app,gateway,token


@pytest.mark.parametrize('source',['archive','live'])
@pytest.mark.parametrize('outgoing',[False,True],ids=['received','sent'])
def test_original_lottie_zip_is_verified_and_downloadable(environment,source,outgoing):
    app,gateway,token=setup_lottie(environment,outgoing=outgoing)
    with TestClient(app) as client:
        headers(client,token)
        if source=='archive': acquire(app.state.service,gateway)
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':source})
        assert app.state.service.media.process_one()
        ready=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert ready['state']=='ready'
        assert ready['mimetype']=='application/was'
        assert ready['filename']=='MEDIAFORMAT.zip'
        assert ready['size']==len(gateway.media_bytes)
        assert ready['sha256']==hashlib.sha256(gateway.media_bytes).hexdigest()
        client.headers.pop('Authorization')
        response=client.get(ready['download_url'])
        assert response.status_code==200
        assert response.content==gateway.media_bytes
        assert response.headers['content-type']=='application/was'
        assert 'MEDIAFORMAT.zip' in response.headers['content-disposition']
        assert response.headers['x-content-type-options']=='nosniff'
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert archive.testzip() is None
            animation=json.loads(archive.read('animation/animation.json'))
            assert animation['w']==animation['h']==16
        assert not gateway.sent


def test_old_acquired_webp_summary_can_fetch_verified_original_after_provider_upgrade(environment):
    app,gateway,token=setup_lottie(environment)
    with TestClient(app) as client:
        headers(client,token)
        gateway.observation['media'].update(mimetype='image/webp',filename='MEDIAFORMAT.webp')
        acquire(app.state.service,gateway)
        # The acquired typed WAS digest is retained. The upgraded provider now
        # exposes its original bytes under a distinct ZIP cache key.
        gateway.observation['media'].update(mimetype='application/was',filename='MEDIAFORMAT.zip')
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':'archive'})
        assert app.state.service.media.process_one()
        ready=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert ready['state']=='ready'
        assert ready['filename']=='MEDIAFORMAT.zip'
        assert ready['sha256']==hashlib.sha256(gateway.media_bytes).hexdigest()
        assert client.get(ready['download_url']).content==gateway.media_bytes


@pytest.mark.parametrize('source',['archive','live'])
def test_legacy_transformed_lottie_contract_remains_rejected(environment,source):
    app,gateway,token=setup_lottie(environment)
    gateway.observation['media'].update(mimetype='image/webp',filename='MEDIAFORMAT.webp')
    gateway.media_bytes=(FIXTURES/'sample.webp').read_bytes()
    with TestClient(app) as client:
        headers(client,token)
        if source=='archive': acquire(app.state.service,gateway)
        response=call(client,'get_attachment',{'message_id':gateway.observation['id'],'source':source})['result']
        if source=='live':
            assert response.get('isError')
        else:
            queued=response['structuredContent']
            assert app.state.service.media.process_one()
            failed=result(client,'get_transfer_status',{'transfer_id':queued['id']})
            assert failed['state']=='failed'
            assert 'download_url' not in failed
            assert not app.state.service.media.path(queued['id']).exists()
        assert not gateway.downloads


@pytest.mark.parametrize('failure',['transformed_bytes','wrong_size'])
def test_original_lottie_contract_does_not_relax_hash_or_size_verification(environment,failure):
    app,gateway,token=setup_lottie(environment)
    with TestClient(app) as client:
        headers(client,token)
        acquire(app.state.service,gateway)
        queued=result(client,'get_attachment',{'message_id':gateway.observation['id'],'source':'archive'})
        if failure=='transformed_bytes':
            gateway.media_bytes=(FIXTURES/'sample.webp').read_bytes()
        else:
            gateway.observation['_data']['Message']['stickerMessage']['fileLength']='1'
        assert app.state.service.media.process_one()
        failed=result(client,'get_transfer_status',{'transfer_id':queued['id']})
        assert failed['state']=='failed'
        assert failed['sha256'] is None
        assert 'download_url' not in failed
        assert not app.state.service.media.path(queued['id']).exists()
